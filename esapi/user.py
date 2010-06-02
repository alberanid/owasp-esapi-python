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

from esapi.core import ESAPI
from esapi.translation import _

class User(object):
    """
    The User interface represents an application user or user account. There 
    is quite a lot of information that an application must store for each user 
    in order to enforce security properly. There are also many rules that 
    govern authentication and identity management.

    A user account can be in one of several states. When first created, a User
    should be disabled, not expired, and unlocked. To start using the account, 
    an administrator should enable the account. The account can be locked for a
    number of reasons, most commonly because they have failed login for too 
    many times. Finally, the account can expire after the expiration date has
    been reached. The User must be enabled, not expired, and unlocked in order 
    to pass authentication.

    @author: Craig Younkins (craig.younkins@owasp.org)
    @since: July 15, 2009
    """
    
    def __init__(self):
        # Security event dictionary, used by the IntrusionDetector
        self.event_map = {}
        
    # Login
    def login_with_password(self, password):
        """
        Login with a password.
        
        @param password: the password
        @raises AuthenticationException: if login fails
        """
        raise NotImplementedError()
        
    def logout(self):
        """
        Logout this user. Implementations should call
        ESAPI.authenticator().logout(self)
        """
        raise NotImplementedError()
        
    def is_logged_in(self):
        """
        Checks if this user is currently logged in.
        
        @return: true if the user is logged in
        """
        raise NotImplementedError()
        
    # Locale
    def _get_locale(self):
        """
        @return: the user's locale
        """
        raise NotImplementedError()
        
    def _set_locale(self, locale):
        """
        @param locale: the locale to set
        """
        raise NotImplementedError()
        
    locale = property( _get_locale, _set_locale )
        
    # Roles
    def add_role(self, role):
        """
        Adds a role to this user's account.
        
        @param role: the role to add
        @raises AuthenticationException:
        """
        raise NotImplementedError()
        
    def remove_role(self, role):
        """
        Removes a role from this user's account.
        
        @param role: the role to remove
        @raises AuthenticationException:
        """
        raise NotImplementedError()
        
    def is_in_role(self, role):
        """
        Checks if this user's account is assigned a particular role.
        
        @param role: the role for which to check.
        @return: true if the role has been assigned to the user.
        """
        raise NotImplementedError()
        
    def _get_roles(self):
        """
        Gets the roles assigned to a particular account.
        
        @return: a tuple of the roles of the current user
        """
        raise NotImplementedError()

    def _set_roles(self, roles):
        """
        Sets the roles for this account.
        
        @param roles: the new roles
        @raises AuthenticationException:
        """
        raise NotImplementedError()
    
    roles = property( _get_roles,
                      _set_roles,
                      doc="The roles assigned to a particular user" )
      
    def add_roles(self, roles):
        """
        Adds a list of roles to this user's account.
        
        @param roles: A list of roles to add.
        @raises AuthenticationException:
        """
        raise NotImplementedError()
      
    # Passwords
    def verify_password(self, password):
        """
        Verify that the supplied password matches the password for this user.
        This method is typically used for 'reauthentication' for the most
        sensitive functions, such as transactions, changing email address,
        and changing other account information.
        
        @param password: the password that the user entered
        @return: true if the password matches the account's password
        @raises EncryptionException:
        """
        raise NotImplementedError()
        
    def change_password(self, old_password, new_password1, new_password2):
        """
        Sets the user's password, performing a verification of the user's old
        password, the equality of the two new passwords, and the strength of
        the new password.
        
        Be sure to send in separate form values for the two new passwords.
        Do NOT send in the same form value.
        
        @param old_password: the old password
        @param new_password1: the new password
        @param new_password2: the new password again, used to verify that that
            the new password was typed correctly. 
        """
        raise NotImplementedError()
        
    def _get_last_password_change_time(self):
        """
        Gets the date of the user's last password change.
        
        @return: a datetime of the last password change.
        """
        raise NotImplementedError()
        
    def _set_last_password_change_time(self, time):
        """
        Sets the time of the last password change for this user.
        
        @param time: the date and time when the user last changed his/her password.
        """
        raise NotImplementedError()
        
    last_password_change_time = property( _get_last_password_change_time,
                                          _set_last_password_change_time,
                                          doc="The time of the last password change for this user." )
        
    # Enable/Disable
    def disable(self):
        """
        Disable this user's account.
        """
        raise NotImplementedError()
        
    def enable(self):
        """
        Enable this user's account.
        """
        raise NotImplementedError()
        
    def is_enabled(self):
        """
        Checks if this user's account is currently enabled.
        
        @return: true if the user is enabled.
        """
        raise NotImplementedError()
        
    # Account id
    def _get_account_id(self):
        """
        Gets this user's account id number.
        
        @return: the account id
        """
        raise NotImplementedError()
        
    account_id = property(_get_account_id,
                          doc="The User's account ID")
        
    # Account name
    def _get_account_name(self):
        """
        Gets this user's account name.
        
        @return: the account name
        """
        raise NotImplementedError()
        
    def _set_account_name(self, name):
        """
        Sets this user's account name.
        
        @param name: the new account name
        """
        raise NotImplementedError()
        
    account_name = property(_get_account_name, 
                            _set_account_name,
                            doc="The User's account name")
        
    # CSRF tokens
    def _get_csrf_token(self):
        """
        Gets the CSRF token for this user's current session.
        
        @return: the CSRF token
        """
        raise NotImplementedError()
    
    csrf_token = property( _get_csrf_token,
                           doc="The User's CSRF token")
        
    def reset_csrf_token(self):
        """
        Returns a token to be used as a prevention against CSRF attacks. This
        token should be added to all links and forms. The application should
        verify that all requests contain the token, or they may have been
        generated by a CSRF attack. It is generally best to perform the check
        in a centralized location, either a filter or controller.

        @see: L{esapi.reference.default_http_utilities.verify_csrf_token}
        @return: the new CSRF token
        @raises AuthenticationException:
        """
        raise NotImplementedError()
        
    # Expiration
    def _get_expiration_time(self):
        """
        Gets the date that this user's account will expire.
        
        @return: a datetime of when the account will expire.
        """
        raise NotImplementedError()
        
    def _set_expiration_time(self, expiration_time):
        """
        Sets the date and time when this user's account will expire.
        
        @param expiration_time: the new expiration time
        """
        raise NotImplementedError()
       
    expiration_time = property( _get_expiration_time,
                                _set_expiration_time,
                                doc="The date and time that this User's account will expire" )
        
    def is_expired(self):
        """
        Checks if this user's account is expired.
        
        @return: true if the account is expired
        """
        raise NotImplementedError()
        
    # Failed logins
    def get_failed_login_count(self):
        """
        Returns the number of failed login attempts since the last successful
        login for an account. This method is intended to be used as a part of 
        the account lockout feature, to help protect against brute force
        attacks. However, the implementor should be aware that lockouts can be
        used to prevent access to an application by a legitimate user, and
        should consider the risk of denial of service.
        
        @return: the number of failed login attempts since the last successful
            login
        """
        raise NotImplementedError()
        
    def increment_failed_login_count(self):
        """
        Increment the failed login count.
        """
        raise NotImplementedError()
        
    def _get_last_failed_login_time(self):
        """
        Gets the date of the last failed login time for a user. This date
        should be used in a message to users after a successful login, to
        notify them of potential attack activity on their account.
        
        @return: a datetime of the last failed login
        """
        raise NotImplementedError()
        
    def _set_last_failed_login_time(self, time):
        """
        Set the date and time of the last failed login for this user.
        
        @param time: the date and time when the user last failed to login 
            correctly.
        """
        raise NotImplementedError()
        
    last_failed_login_time = property( _get_last_failed_login_time,
                                       _set_last_failed_login_time,
                                       doc="The date and time of the last failed login for the user." )
        
    # Host address
    def _get_last_host_address(self):
        """
        Gets the last host address used by the user. This will be used in any
        log messages generated by the processing of a request.
        
        @return: the last host address used by the user
        """
        raise NotImplementedError()
        
    def _set_last_host_address(self, address):
        """
        Sets the last remote host address used by this user.
        
        @param address: The address of the user's current source host.
        """
        raise NotImplementedError()
        
    last_host_address = property( _get_last_host_address,
                             _set_last_host_address,
                             doc="The last host address used by this user" )
        
    # Login times
    def _get_last_login_time(self):
        """
        Gets the date of the last successful login time for a user. This date
        should be used in a message to the user after a successful login, to 
        notify them of potential attack activity on their account.
        
        @return: a datetime of the last successful login
        """
        raise NotImplementedError()
        
    def _set_last_login_time(self, time):
        """
        Sets the time of the last successful login for this user.
        
        @param time: the date and time when the user last successfully logged
            in.
        """
        raise NotImplementedError()
        
    last_login_time = property( _get_last_login_time,
                                _set_last_login_time,
                                doc="The date and time the user last successfully logged in." )
       
    # Screen names  
    def _get_screen_name(self):
        """
        Gets the screen name (alias) for this user.
        
        @return: the screen name of the current user
        """
        raise NotImplementedError()
        
    def _set_screen_name(self, new_screen_name):
        """
        Sets the screen name (alias) for this user.
        
        @param new_screen_name: the new screen name
        """
        raise NotImplementedError()
        
    screen_name = property( _get_screen_name,
                            _set_screen_name,
                            doc="The screen name or alias for the User" )
                            
    # Session
    def add_session(self, session):
        """
        Adds a session for this User.
        
        @param session: the session to associate with this user.
        """
        raise NotImplementedError()
        
    def remove_session(self, session):
        """
        Removes a session for this User.
        
        @param session: the session to dissociate with this user.
        """
        raise NotImplementedError()
        
    def get_sessions(self):
        """
        Returns the list of sessions associated with this user.
        
        @return: a tuple of the user's sessions.
        """
        raise NotImplementedError()
    
    # Anonymous user
    def is_anonymous(self):
        """
        Checks if the user is anonymous.
        
        @return: true if the user is anonymous
        """
        raise NotImplementedError()
        
    # Timeouts
    def is_session_absolute_timeout(self):
        """
        Checks if this user's session has exceeded the absolute time out based
        on ESAPI's configuration.
        
        @return: true if the user's session has exceed the absolute time out.
        """
        raise NotImplementedError()
        
    def is_session_timeout(self):
        """
        Checks if the user's session has timed out from inactivity based on
        ESAPI's configuration.
        
        @return: true if the user's session has timed out from inactivity
            based on ESAPI's configuration.
        """
        raise NotImplementedError()
    
    # Locking
    def lock(self):
        """
        Lock this user's account.
        """
        raise NotImplementedError()
        
    def unlock(self):
        """
        Unlock this user's account.
        """
        raise NotImplementedError()
        
    def is_locked(self):
        """
        Checks if this user's account is locked.
        
        @return: true of the account is locked
        """
        raise NotImplementedError()
       
    # Security event dictionary 
    def get_event_dict(self):
        """
        Gets the dictionary used to store security events for this user. Used
        by the IntrusionDetector.
        """
        raise NotImplementedError()
        
######################

class AnonymousUser(object):  
    def __init__(self):
        self._account_name = 'Anonymous'
        
    # Login
    def login_with_password(self, password):
        raise NotImplementedError()
        
    def logout(self):
        raise NotImplementedError()
        
    def is_logged_in(self):
        raise NotImplementedError()
        
    # Locale
    def _get_locale(self):
        raise NotImplementedError()
        
    def _set_locale(self, locale):
        raise NotImplementedError()
        
    locale = property( _get_locale, _set_locale )
        
    # Roles
    def add_role(self, role):
        raise NotImplementedError()
        
    def remove_role(self, role):
        raise NotImplementedError()
        
    def is_in_role(self, role):
        raise NotImplementedError()
        
    def _get_roles(self):
        return []

    def _set_roles(self, roles):
        raise NotImplementedError()
    
    roles = property( _get_roles,
                      _set_roles,
                      doc="The roles assigned to a particular user" )
      
    def add_roles(self, roles):
        raise NotImplementedError()
      
    # Passwords
    def verify_password(self, password):
        raise NotImplementedError()
        
    def change_password(self, old_password, new_password1, new_password2):
        raise NotImplementedError()
        
    def _get_last_password_change_time(self):
        raise NotImplementedError()
        
    def _set_last_password_change_time(self, time):
        raise NotImplementedError()
        
    last_password_change_time = property( _get_last_password_change_time,
        _set_last_password_change_time,
        doc="The time of the last password change for this user." )
        
    # Enable/Disable
    def disable(self):
        raise NotImplementedError()
        
    def enable(self):
        raise NotImplementedError()
        
    def is_enabled(self):
        raise NotImplementedError()
        
    # Account id
    def _get_account_id(self):
        raise NotImplementedError()
        
    account_id = property(_get_account_id,
                          doc="The User's account ID")
        
    # Account name
    def _get_account_name(self):
        return self._account_name
        
    def _set_account_name(self, name):
        raise NotImplementedError()
        
    account_name = property(_get_account_name, 
                            _set_account_name,
                            doc="The User's account name")
        
    # CSRF tokens
    def _get_csrf_token(self):
        return ""
    
    csrf_token = property( _get_csrf_token,
                           doc="The User's CSRF token")
        
    def reset_csrf_token(self):
        raise NotImplementedError()
        
    # Expiration
    def _get_expiration_time(self):
        raise NotImplementedError()
        
    def _set_expiration_time(self, expiration_time):
        raise NotImplementedError()
       
    expiration_time = property( _get_expiration_time,
                                _set_expiration_time,
                                doc="The date and time that this User's account will expire" )
        
    def is_expired(self):
        raise NotImplementedError()
        
    # Failed logins
    def get_failed_login_count(self):
        raise NotImplementedError()
        
    def increment_failed_login_count(self):
        raise NotImplementedError()
        
    def _get_last_failed_login_time(self):
        raise NotImplementedError()
        
    def _set_last_failed_login_time(self, time):
        raise NotImplementedError()
        
    last_failed_login_time = property( _get_last_failed_login_time,
        _set_last_failed_login_time,
        doc="The date and time of the last failed login for the user." )
        
    # Host address
    def _get_last_host_address(self):
        return "unknown"
        
    def _set_last_host_address(self, address):
        raise NotImplementedError()
        
    last_host_address = property( _get_last_host_address,
                             _set_last_host_address,
                             doc="The last host address used by this user" )
        
    # Login times
    def _get_last_login_time(self):
        raise NotImplementedError()
        
    def _set_last_login_time(self, time):
        raise NotImplementedError()
        
    last_login_time = property( _get_last_login_time,
                                _set_last_login_time,
                                doc="The date and time the user last successfully logged in." )
       
    # Screen names  
    def _get_screen_name(self):
        raise NotImplementedError()
        
    def _set_screen_name(self, new_screen_name):
        raise NotImplementedError()
        
    screen_name = property( _get_screen_name,
                            _set_screen_name,
                            doc="The screen name or alias for the User" )
                            
    # Session
    def add_session(self, session):
        return None
        
    def remove_session(self, session):
        return None
        
    def get_sessions(self):
        raise NotImplementedError()
    
    # Anonymous user
    def is_anonymous(self):
        return True
        
    # Timeouts
    def is_session_absolute_timeout(self):
        raise NotImplementedError()
        
    def is_session_timeout(self):
        raise NotImplementedError()
    
    # Locking
    def lock(self):
        raise NotImplementedError()
        
    def unlock(self):
        raise NotImplementedError()
        
    def is_locked(self):
        raise NotImplementedError()
       
    # Security event dictionary 
    def get_event_dict(self):
        raise NotImplementedError()
