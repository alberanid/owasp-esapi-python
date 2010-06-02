#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@copyright: Copyright (c) 2009 - The OWASP Foundation
@summary: The User interface represents an application user or user account.
@author: Craig Younkins (craig.younkins@owasp.org)
"""

# Todo
# Change many things after authenticator, httpUtilities written
# Some methods not implemented
# Safe initial values

from datetime import datetime, timedelta

from esapi.core import ESAPI
from esapi.translation import _
from esapi.user import User
from esapi.encoder import Encoder
from esapi.exceptions import AuthenticationAccountsException, AuthenticationLoginException, AuthenticationHostException
from esapi.logger import Logger

class DefaultUser(User):
    """
    The reference implementation of the User interface. This implementation
    is pickled/shelved into a flat file.
    """
    
    IDLE_TIMEOUT_LENGTH = ESAPI.security_configuration().get_session_idle_timeout_length()
    
    ABSOLUTE_TIMEOUT_LENGTH = ESAPI.security_configuration().get_session_absolute_timeout_length()
    
    MAX_ROLE_LENGTH = 250
    
    def __init__(self, account_name):
        """
        Instantiates a new user.
        
        @param account_name: The name of this user's account.
        """
        User.__init__(self)
        
        self._account_name = None
        self._set_account_name(account_name)
        
        # Get random numbers until we find an unused account number
        # WARNING: This could cause in infinite loop if the number of users equals the keyspace of uids.
        while True:
            id = ESAPI.randomizer().get_random_integer(1)
            if id != 0 and not ESAPI.authenticator().exists(account_id=id):
                self._account_id = id
                break
        
        self.logger = ESAPI.logger("DefaultUser")
        self._screen_name = None
        self._csrf_token = self.reset_csrf_token()
        self._roles = []
        self._locked = False
        self._logged_in = False
        self._enabled = False
        self._last_host_address = None
        self._last_password_change_time = None
        self._last_login_time = datetime.min
        self._last_failed_login_time = datetime.min
        self._expiration_time = datetime.max
        self._sessions = []
        
        # Security event dictionary, used by the IntrusionDetector
        self.event_map = {}
        
        self._failed_login_count = 0
        self._locale = None
        
    # Login
    def login_with_password(self, password):
        if password is None:
            self.last_failed_login_time = datetime.now()
            self.increment_failed_login_count()
            raise AuthenticationLoginException( _("Login failed"),
                _("Missing password: %(account_name)s") %
                {'account_name' : self.account_name})
             
        # Don't let disabled users log in
        if not self.is_enabled():
            self.last_failed_login_time = datetime.now()
            self.increment_failed_login_count()
            raise AuthenticationLoginException( _("Login failed"),
                _("Disabled user attempt to login: %(account_name)s") %
                {'account_name' : self.account_name})
                
        # Don't let locked users log in
        if self.is_locked():
            self.last_failed_login_time = datetime.now()
            self.increment_failed_login_count()
            raise AuthenticationLoginException( _("Login failed"),
                _("Locked user attempt to login: %(account_name)s") %
                {'account_name' : self.account_name})
                
        # Don't let expired users log in
        if self.is_expired():
            self.last_failed_login_time = datetime.now()
            self.increment_failed_login_count()
            raise AuthenticationLoginException( _("Login failed"),
                _("Expired user attempt to login: %(account_name)s") %
                {'account_name' : self.account_name})
                
        self.logout()
        if self.verify_password( password ):
            self._logged_in = True
            ESAPI.http_utilities().change_session_identifier( ESAPI.current_request() )
            ESAPI.authenticator().current_user = self
            self.last_login_time = datetime.now()
            self.last_host_address = ESAPI.http_utilities().get_current_request().remote_host
            self.logger.trace(Logger.SECURITY_SUCCESS, 
                _("User logged in: %(account_name)s") %
                {'account_name' : self.account_name})
        else:
            self._logged_in = False
            self.last_failed_login_time = datetime.now()
            self.increment_failed_login_count()
            if self.get_failed_login_count() >= ESAPI.security_configuration().get_allowed_login_attempts():
                self.lock()
            raise AuthenticationLoginException( _("Login failed"),
                _("Incorrect password provided for %(account_name)s") %
                {'account_name' : self.account_name})
        
    def logout(self):
        return ESAPI.authenticator().logout(self)
        
    def is_logged_in(self):
        return self._logged_in
        
    # Locale
    def _get_locale(self):
        return self._locale
        
    def _set_locale(self, locale):
        self._locale = locale
       
    locale = property( _get_locale, _set_locale )
        
    # Roles
    def add_role(self, role):
        """
        If role is a string, it will be lower()'d.
        """
        if isinstance(role, str):
            role = role.lower()
            
        if ESAPI.validator().is_valid_input("addRole",
                            role, 
                            "RoleName", 
                            DefaultUser.MAX_ROLE_LENGTH, 
                            False):
            if role not in self._roles:
                self._roles.append(role)
                self.logger.info(Logger.SECURITY_SUCCESS,
                     _("Role %(role_name)s added to %(account_name)s") %
                     {'role_name' : role,
                      'account_name' : self.account_name})
            else:
                # Role already assigned
                pass
        else:
            raise AuthenticationAccountsException( _("Add role failed"),
                _("Attempt to add invalid role %(role_name)s to %(account_name)s") %
                {'role_name' : role,
                 'account_name' : self.account_name})
                              
        
    def remove_role(self, role):
        if isinstance(role, str):
            role = role.lower()
            
        try:
            self._roles.remove(role)
            self.logger.trace(Logger.SECURITY_SUCCESS,
                _("Role %(role_name)s removed from %(account_name)") %
                {'role_name' : role,
                 'account_name' : self.account_name})
        except ValueError:
            # Raise an exception?
            pass
        
    def is_in_role(self, role):
        if isinstance(role, str):
            role = role.lower()
            
        return role in self._roles
        
    def _get_roles(self):
        return tuple(self._roles)

    def _set_roles(self, roles):
        self._roles = list(roles)[:]
        
    roles = property( _get_roles,
                      _set_roles,
                      doc="The roles assigned to a particular user" )
      
    def add_roles(self, roles):
        for role in roles:
            self.add_role(role)
      
    # Passwords
    def verify_password(self, password):
        return ESAPI.authenticator().verify_password(self, password)
        
    def change_password(self, old_password, new_password1, new_password2):
        ESAPI.authenticator().change_password(self, 
            old_password, 
            new_password1, 
            new_password2)
        
    def _get_last_password_change_time(self):
        return self._last_password_change_time
        
    def _set_last_password_change_time(self, time):
        self._last_password_change_time = time
        self.logger.info( Logger.SECURITY_SUCCESS,
            _("Set last password change time to %(time)s for %(account_name)s") %
            {'time' : time,
             'account_name' : self.account_name})
        
    last_password_change_time = property( _get_last_password_change_time,
                                          _set_last_password_change_time,
                                          doc="The time of the last password change for this user." )
        
    # Enable/Disable
    def disable(self):
        self._enabled = False
        self.logger.info( Logger.SECURITY_SUCCESS, 
            _("Account disabled: %(account_name)s") %
            {'account_name' : self.account_name})
        
    def enable(self):
        self._enabled = True
        self.logger.info( Logger.SECURITY_SUCCESS,
            _("Account enabled: %(account_name)s") %
            {'account_name' : self.account_name})
        
    def is_enabled(self):
        return self._enabled
        
    # Account id
    def _get_account_id(self):
        return self._account_id
        
    account_id = property(_get_account_id,
                          doc="The User's account ID")
        
    # Account name
    def _get_account_name(self):
        return self._account_name
        
    def _set_account_name(self, name):
        old = self.account_name
        self._account_name = name.lower()
        if old is not None:
            if old == "":
                old = "[nothing]"
            self.logger.info( Logger.SECURITY_SUCCESS,
                _("Account name changed from %(old)s to %(new)s") %
                {'old' : old,
                 'new' : self.account_name} )
                 
    account_name = property(_get_account_name, 
                            _set_account_name,
                            doc="The User's account name")
        
    # CSRF tokens
    def _get_csrf_token(self):
        return self._csrf_token
        
    csrf_token = property( _get_csrf_token,
                           doc="The User's CSRF token")
        
    def reset_csrf_token(self):
        self._csrf_token = ESAPI.randomizer().get_random_string(8, 
            Encoder.CHAR_ALPHANUMERICS)
        return self.csrf_token
        
    # Expiration
    def _get_expiration_time(self):
        return self._expiration_time
        
    def _set_expiration_time(self, expiration_time):
        self._expiration_time = expiration_time
        self.logger.info( Logger.SECURITY_SUCCESS,
            _("Account expiration time was set to %(time)s for %(account_name)s") %
            {'time' : expiration_time,
             'account_name' : self.account_name})

    expiration_time = property( _get_expiration_time,
                _set_expiration_time,
                doc="The date and time that this User's account will expire" )

    def is_expired(self):
        return self.expiration_time < datetime.now()
        
    # Failed logins
    def get_failed_login_count(self):
        return self._failed_login_count
        
    def increment_failed_login_count(self):
        self._failed_login_count += 1
        
    def _get_last_failed_login_time(self):
        return self._last_failed_login_time
        
    def _set_last_failed_login_time(self, time):
        self._last_failed_login_time = time
        self.logger.info( Logger.SECURITY_SUCCESS, 
            _("Set last failed login time to %(time)s for %(user)s") %
            {'time' : time,
             'user' : self.account_name})
             
    last_failed_login_time = property( _get_last_failed_login_time,
                                       _set_last_failed_login_time,
                                       doc="The date and time of the last failed login for the user." )
        
    # Host address
    def _get_last_host_address(self):
        if self._last_host_address is None:
            return "unknown"
        return self._last_host_address
        
    def _set_last_host_address(self, address):
        if (self._last_host_address is not None and 
            self._last_host_address != address):
            raise AuthenticationHostException( _("Host change"),
                _("User sessions just jumped from %(old)s to %(new)s") %
                {'old' : self._last_host_address,
                 'new' : address})
        self._last_host_address = address
        
    last_host_address = property( _get_last_host_address,
                             _set_last_host_address,
                             doc="The last host address used by this user" )
        
    # Login times
    def _get_last_login_time(self):
        return self._last_login_time
        
    def _set_last_login_time(self, time):
        self._last_login_time = time
        self.logger.info( Logger.SECURITY_SUCCESS,
            _("Set last successful login time to %(time)s for %(account_name)s") %
            {'time' : time,
             'account_name' : self.account_name})
             
    last_login_time = property( _get_last_login_time,
        _set_last_login_time,
        doc="The date and time the user last successfully logged in." )
       
    # Screen names  
    def _get_screen_name(self):
        return self._screen_name
        
    def _set_screen_name(self, new_screen_name):
        self._screen_name = new_screen_name
        self.logger.info( Logger.SECURITY_SUCCESS,
            _("ScreenName changed to %(new)s for %(account_name)s") %
            {'new' : new_screen_name,
             'account_name' : self.account_name})
             
    screen_name = property( _get_screen_name,
                            _set_screen_name,
                            doc="The screen name or alias for the User" )
                            
    # Session
    def add_session(self, session):
        self._sessions.append(session)
        
    def remove_session(self, session):
        try:
            self._sessions.remove(session)
        except:
            pass
        
    def get_sessions(self):
        return tuple(self._sessions)
    
    # Anonymous user
    def is_anonymous(self):
        return False
        
    # Timeouts
    def is_session_absolute_timeout(self):
        session = ESAPI.http_utilities().current_request.session
        if session is None:
            return True
            
        deadline = session.creation_time + self.ABSOLUTE_TIMEOUT_LENGTH
        return datetime.now() > deadline
        
    def is_session_timeout(self):
        session = ESAPI.http_utilities().current_request.session
        if session is None:
            return True
            
        deadline = session.last_accessed_time + self.IDLE_TIMEOUT_LENGTH
        return datetime.now() > deadline
    
    # Locking
    def lock(self):
        self._locked = True
        self.logger.info( Logger.SECURITY_SUCCESS,
            _("Account locked: %(account_name)s") %
            {'account_name' : self.account_name})
        
    def unlock(self):
        self._locked = False
        self._failed_login_count = 0
        self.logger.info( Logger.SECURITY_SUCCESS,
            _("Account unlocked: %(account_name)s") % 
            {'account_name' : self.account_name})
        
    def is_locked(self):
        return self._locked
        
    def __getstate__(self):
        # Copy the object's state from self.__dict__ which contains
        # all our instance attributes. Always use the dict.copy()
        # method to avoid modifying the original state.
        state = self.__dict__.copy()
        # Remove the unpicklable entries.
        del state['logger']
        return state

    def __setstate__(self, state):
        """
        Restore unpickleable instance attributes like logger.
        """
        self.__dict__.update(state)
        self.logger = ESAPI.logger("DefaultUser")
