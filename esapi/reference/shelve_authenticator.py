#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: A reference implementation
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

# Todo
# Fix get_user_from_remember_token after seal/unseal written

import shelve
from datetime import datetime

from esapi.core import ESAPI
from esapi.translation import _
from esapi.logger import Logger
from user_credentials import UserCredentials
from esapi.authenticator import Authenticator
from esapi.encoder import Encoder
from esapi.http_utilities import HTTPUtilities
import esapi.user
from esapi.exceptions import AuthenticationException, AuthenticationAccountsException, AuthenticationLoginException, AccessControlException, AuthenticationCredentialsException, EncryptionException, EnterpriseSecurityException

class ShelveAuthenticator(Authenticator):
    """
    This implementation uses Python's shelve module to store serialized
    user objects in a binary file.
    """
    # Key for user in session
    USER = "ESAPIUserSessionKey"
    USERS_FILENAME = "users.shelf"
    CREDS_FILENAME = "creds.shelf"
    MAX_ACCOUNT_NAME_LENGTH = 250
    MIN_PASSWORD_STRENGTH = 16
    
    def __init__(self):
        Authenticator.__init__(self)
        self.logger = ESAPI.logger("Authenticator")
        
        users_filename = ESAPI.security_configuration().get_resource_file(self.USERS_FILENAME)
        self.user_shelf = shelve.open(users_filename, writeback=True)
        
        cred_filename = ESAPI.security_configuration().get_resource_file(self.CREDS_FILENAME)
        self.cred_shelf = shelve.open(cred_filename, writeback=True)
        self.current_user = esapi.user.AnonymousUser()
        
    def clear_current(self):
        self.current_user = esapi.user.AnonymousUser()
        
    def clear_all_data(self):
        self.user_shelf.clear()
        self.cred_shelf.clear()
        
    def login(self, request=None, response=None):
        if request is None:
            request = ESAPI.current_request()
        
        if response is None:
            response = ESAPI.current_response()
            
        # if there's a user in the session than use that
        user = self.get_user_from_session()
        
        # else if there is a remember token then use that
        if user is None:
            user = self.get_user_from_remember_token()
            
        # else try to verify credentials
        # throws exception if login fails
        if user is None:
            user = self.login_with_username_and_password(request, response)
            
        # set last host address
        user.last_host_address = request.remote_host
        
        # Warn if this authentication request was not POST or non-SSL 
        # connection, exposing credentials or session id
        try:
            ESAPI.http_utilities().assert_secure_request( request )
        except AccessControlException, extra:
            raise AuthenticationException(
                _("Attempt to login with an insecure request"),
                extra=extra )
                
                
        # anonymous users cannot login
        if user.is_anonymous():
            user.logout()
            self.user_shelf.sync()
            raise AuthenticationLoginException(
                _("Login failed"),
                _("Anonymous user cannot be set to current user. User: %(user)s") %
                {'user' : user.account_name} )
                
        def failed_login(user, reason):
            user.logout()
            user.increment_failed_login_count()
            user.last_failed_login_count = datetime.now()
            self.user_shelf.sync()
            raise AuthenticationLoginException(
                _("Login failed"),
                reason + _(" User: %(user)s") %
                {'user' : user.account_name})
                
        # disabled users cannot login
        if not user.is_enabled():
            failed_login( user, 
                _("Disabled user cannot be set to current user.") )
                
        # locked users cannot login
        if user.is_locked():
            failed_login( user,
                _("Locked user cannot be set to current user.") )
                
                
        # Expired users cannot login
        if user.is_expired():
            failed_login( user,
                _("Expired user cannot be set to current user.") )
                
        # Check session inactivity timeout
        if user.is_session_timeout():
            failed_login( user,
                _("Session inactivity timeout.") )
                
        # Check session absolute timeout
        if user.is_session_absolute_timeout():
            failed_login( user,
                _("Session absolute timeout.") )
                
        # set locale to the user object in the session from request
        user.locale = request.headers['Accept-Language']
        
        session = request.session
        user.add_session( session )
        session[self.USER] = user
        self.current_user = user
        self.user_shelf.sync()
        
        return user
        
    def login_with_username_and_password(self, request, response):
        username_param = ESAPI.security_configuration().get_username_parameter_name()
        password_param = ESAPI.security_configuration().get_password_parameter_name()
        
        username = request.POST.get(username_param, None)
        password = request.POST.get(password_param, None)
        
        # if a logged-in user is requesting login, log them out first
        if self.current_user is not None and not self.current_user.is_anonymous():
            self.logger.warning( Logger.SECURITY_SUCCESS,
                _("User requested relogin. Performing logout then authentication") )
            self.current_user.logout()
            
        # Authenticate with username and password
        if username is None or password is None:
            if username is None:
                username = "unspecified user"
                
            raise AuthenticationCredentialsException(
                _("Authentication failed"),
                _("Authentication failed for %(user)s because of null username or password") %
                {'user' : username} )
                
        user = self.get_user(username)
        if user is None:
            raise AuthenticationCredentialsException(
                _("Authentication failed"),
                _("Authentication failed because user %(user)s doesn't exist") %
                {'user' : username} )
         
        user.login_with_password(password)
        
        request.headers[user.csrf_token] = 'authenticated'
        return user
        
    def get_user_from_session(self):
        session = ESAPI.http_utilities().get_current_request().session
        if session is None:
            return None
        return session.get(self.USER, None)
        
    def get_user_from_remember_token(self):   
        try:
            token = ESAPI.http_utilities().get_cookie(  
                HTTPUtilities.REMEMBER_TOKEN_COOKIE_NAME,
                ESAPI.current_request() )
            if token is None:
                return None
            data = ESAPI.encryptor().unseal( token ).split('|')
            if len(data) != 2:
                self.logger.warning( Logger.SECURITY_FAILURE,
                    _("Found corrupt or expired remember token") )
                ESAPI.http_utilities().kill_cookie( 
                    HTTPUtilities.REMEMBER_TOKEN_COOKIE_NAME,
                    ESAPI.current_request(), 
                    ESAPI.current_response() )
                return None
            
            username, password = data
            user = self.get_user(account_name=username)
            if user is None:
                self.logger.warning( Logger.SECURITY_FAILURE,
                    _("Found valid remember token but no user matching %(username)s") %
                    {'username' : username} )
                return None
                
            self.logger.info( Logger.SECURITY_SUCCESS,
                _("Logging in user with remember token: %(username)s") %
                {'username' : user.account_name} )
            user.login_with_password(password)
            self.user_shelf.sync()
            return user
        except AuthenticationException, extra:
            self.logger.warning( Logger.SECURITY_FAILURE,
                _("Login via remember me cookie failed"),
                extra=extra )
        except EnterpriseSecurityException, extra:
            self.logger.warning( Logger.SECURITY_FAILURE,
                _("Remember token was missing, corrupt, or expired") )
                
        ESAPI.http_utilities().kill_cookie( 
            HTTPUtilities.REMEMBER_TOKEN_COOKIE_NAME, 
            ESAPI.current_request(), 
            ESAPI.current_response() )
            
        return None  
        
    def verify_password(self, user, password):
        try:
            hash = self.hash_password(password, user.account_name)
            current_hash = self.get_hashed_password(user)
            if hash == current_hash:
                user.last_login_time = datetime.now()
                user.failed_login_count = 0
                self.logger.info( Logger.SECURITY_SUCCESS,
                    _("Password verified for %(user)s") %
                    {'user' : user.account_name} )
                return True
        except EncryptionException, extra:
            self.logger.fatal( Logger.SECURITY_FAILURE,
                _("Encryption error verifying password for %(user)s") %
                {'user' : user.account_name} )
        self.logger.fatal( Logger.SECURITY_FAILURE,
            _("Password verification failed for %(user)s") %
            {'user' : user.account_name} )
        return False
        
    def get_hashed_password(self, user):
        key = user.account_name
        credentials = self.cred_shelf.get(key, None)
        if credentials is None:
            return None
            
        return credentials.get_hashed_password()
        
    def set_hashed_password(self, user, new_hash):
        key = user.account_name
        credentials = self.cred_shelf.get(key, None)
        if credentials is None:
            self.cred_shelf[key] = UserCredentials(key)
            credentials = self.cred_shelf.get(key, None)
        
        credentials.change_password(new_hash)
        
    def logout(self, user=None):
        if user is None:
            user = self.current_user
            
        if user is not None and not user.is_anonymous():
            ESAPI.http_utilities().kill_cookie( 
                HTTPUtilities.REMEMBER_TOKEN_COOKIE_NAME,
                ESAPI.current_request(), 
                ESAPI.current_response() )
            
            session = ESAPI.current_request().session
            
            if session is not None:
                user.remove_session(session)
                session.invalidate()
                
            ESAPI.http_utilities().kill_cookie( 
                ESAPI.http_utilities().SESSION_TOKEN_NAME, 
                ESAPI.current_request(),
                ESAPI.current_response() )
            user._logged_in = False
            self.logger.info(Logger.SECURITY_SUCCESS, _("Logout successful"))
            self.current_user = esapi.user.AnonymousUser()
            
    def create_user(self, account_name, password1, password2):
        if account_name is None:   
            raise AuthenticationAccountsException(
                _("Account creation failed"),
                _("Attempt to create user with None account_name") )
        
        if self.get_user(account_name) is not None:
            raise AuthenticationAccountsException(
                _("Account creation failed"),
                _("Duplicate user creation denied for %(user)s") % 
                {'user' : account_name} )
        
        account_name = account_name.lower()
        self.verify_account_name_strength(account_name)
        
        if password1 is None or password2 is None:
            raise AuthenticationCredentialsException(
                _("Invalid account name"),
                _("Attempt to create account %(user)s with a None password") %
                {'user' : account_name} )
                
        self.verify_password_strength(password1)
        
        if password1 != password2:
            raise AuthenticationCredentialsException(
                _("Passwords do not match"),
                _("Passwords for %(user)s do not match") %
                {'user' : account_name} )
               
        klass = ESAPI.security_configuration().get_class_for_interface('user')
        user = klass(account_name)
        
        try:
            self.set_hashed_password(user, self.hash_password(password1, account_name))
            user.last_password_change_time = datetime.now()
        except EncryptionException, extra:
            raise AuthenticationException(
                _("Internal error"),
                _("Error hashing password for %(user)s") % 
                {'user' : account_name},
                extra )
                
        self.user_shelf[account_name] = user
        self.logger.info( Logger.SECURITY_SUCCESS,
            _("New user created: %(user)s") %
            {'user' : account_name} )
        self.user_shelf.sync()  
        return self.user_shelf[account_name]
        
    def generate_strong_password(self):
        """
        Generates a strong password between 7 and 9 characters in length from
        a charset including uppercase and lowercase letters, numbers, and
        special characters. It excludes the confusing characters.
        """
        randomizer = ESAPI.randomizer()
        length = randomizer.get_random_integer(7, 9)
        
        def gen_password():
            return ESAPI.randomizer().get_random_string( 
                length, 
                Encoder.CHAR_PASSWORD_ALL )
            
        new_password = gen_password()
        # Verify we meet password complexity requirements
        success = False
        while not success:
            try:
                self.verify_password_strength(new_password)
                success = True
            except AuthenticationCredentialsException:
                new_password = gen_password()
                
        return new_password
        
    def change_password(self, user, current_password, new_password1, new_password2):
        try:
            current_hash = self.get_hashed_password(user)
            verify_hash = self.hash_password(current_password, user.account_name)
            if current_hash != verify_hash:
                raise AuthenticationCredentialsException(
                    _("Password change failed"),
                    _("Authentication failed for password change on user: %(user)s") %
                    {'user' : user.account_name} )
            
            if (new_password1 is None or 
                new_password2 is None or 
                new_password2 != new_password2):
                raise AuthenticationCredentialsException(
                    _("Password change failed"),
                    _("New passwords do not match for password change on user: %(user)s") %
                    {'user' : user.account_name} )
                    
            self.verify_password_strength(new_password1, current_password)
            user.last_password_change_time = datetime.now()
            
            new_hash = self.hash_password(new_password1, user.account_name)
            if new_hash in self.get_old_password_hashes(user.account_name):
                raise AuthenticationCredentialsException(
                    _("Password change failed"),
                    _("Password matches a recent password for user: %(user)s") %
                    {'user' : user.account_name} )
                    
            self.set_hashed_password(user, new_hash)
            self.logger.info( Logger.SECURITY_SUCCESS,
                _("Password changed for user: %(user)s") %
                {'user' : user.account_name} )
                
        except EncryptionException, extra:
            raise AuthenticationException(
                _("Password change failed"),
                _("Encryption exception changing password for %(user)s") %
                {'user' : user.account_name},
                extra )
        
    def get_user(self, account_name=None, account_id=None):
        if account_name is not None:
            account_name = account_name.lower()
            return self.user_shelf.get(account_name, None)
            
        elif account_id is not None:
            # This is a bad nieve search and should be changed according to your system.
            # SQL can do this much better
            for user in self.user_shelf.values():
                if user.account_id == account_id:
                    return user
            return None
    
    def hash_password(self, password, account_name):
        salt = account_name.lower()
        return ESAPI.encryptor().hash(password, salt)
        
    def remove_user(self, account_name):
        account_name = account_name.lower()
        user = self.get_user(account_name)
        if user is None:
            raise AuthenticationAccountsException(
                _("Remove user failed"),
                _("Can't remove invalid account_name: %(user)s") %
                {'user' : account_name} )
        
        del self.user_shelf[account_name]
        self.logger.info( Logger.SECURITY_SUCCESS,
            _("User successfully removed: %(user)s") %
            {'user' : account_name} )
        self.user_shelf.sync()
        
    def verify_account_name_strength(self, account_name):
        if account_name is None:
            raise AuthenticationCredentialsException(
                _("Invalid account name"),
                _("Attempt to create account with a None account name") )
                
        if not ESAPI.validator().is_valid_input(
            "verifyaccountNameStrength",
            account_name,
            "AccountName",
            self.MAX_ACCOUNT_NAME_LENGTH,
            False):
            raise AuthenticationCredentialsException(
                _("Invalid account name"),
                _("New account name is not valid: %(user)s") %
                {'user' : account_name} )
        
    def verify_password_strength(self, new_password, old_password=None):
        if new_password is None:
            raise AuthenticationCredentialsException(
                _("Invalid password"),
                _("New password cannot be None") )
                
        # Can't change to a password that contains any 3 character substring 
        # of old password
        if old_password is not None:
            for i in range( 0, len(old_password) - 2 ):
                sub = old_password[i:i+3]
                if sub in new_password:
                    raise AuthenticationCredentialsException(
                        _("Invalid password"),
                        _("New password cannot contain pieces of old password.") )
                        
        # new password must have enough character sets and length
        num_charsets = 0
        charsets = [Encoder.CHAR_PASSWORD_LOWERS, 
                    Encoder.CHAR_PASSWORD_UPPERS,
                    Encoder.CHAR_PASSWORD_DIGITS,
                    Encoder.CHAR_PASSWORD_SPECIALS]
        for charset in charsets:
            for c in new_password:
                if c in charset:
                    num_charsets += 1
                    break
                    
        # calculate strength = length * charsets
        strength = len(new_password) * num_charsets
        if strength < self.MIN_PASSWORD_STRENGTH:
            raise AuthenticationCredentialsException(
                _("Invalid password"),
                _("New password is not long or complex enough") )
        
    def exists(self, account_name=None, account_id=None):     
        if account_name is not None:
            account_name = account_name.lower()
            return self.user_shelf.has_key(account_name)
            
        elif account_id is not None:
            # This is a bad nieve search and should be changed according to your system.
            # SQL can do this much better
            for user_name in self.user_shelf.keys():
                user = self.user_shelf[user_name]
                if user.account_id == account_id:
                    return True
            return False
        
    def get_old_password_hashes(self, account_name):
        if self.exists(account_name):
            return self.cred_shelf[account_name].get_old_password_hashes()
        else:
            return []
    
    
