#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: Test suite for User interface.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

# Todo
# Implement any 'pass' methods
# Regroup in same groups as User interface

# Use esapi/test/conf instead of esapi/conf
# It is important that this is at the top, as it affects the imports below
# by loading the test configuration instead of the normal one.
# This should ONLY ever be used in the unit tests.
import esapi.test.conf

import unittest
import inspect
import time
from datetime import datetime, timedelta

from esapi.core import ESAPI
from esapi.translation import _
from esapi.exceptions import AuthenticationLoginException, AuthenticationException
from esapi.reference.default_encoder import DefaultEncoder
from esapi.test.http.mock_http_request import MockHttpRequest
from esapi.test.http.mock_http_response import MockHttpResponse

class UserTest(unittest.TestCase):
    def __init__(self, test_name=""):
        """       
        @param test_name: the test name
        """     
        unittest.TestCase.__init__(self, test_name)
        self.user_class = ESAPI.security_configuration().get_class_for_interface('user')
        
    def setUp(self):
        request = MockHttpRequest()
        response = MockHttpResponse()
        ESAPI.http_utilities().set_current_http(request, response)
        ESAPI.authenticator().logout()
        ESAPI.authenticator().clear_all_data()
             
    def create_test_user(self, username=None, password=None):
        """
        Creates a test user.
        
        @return: the test user
        @raises AuthenticationException:
        """
        if username is None:
            username = ESAPI.randomizer().get_random_string(8, DefaultEncoder.CHAR_ALPHANUMERICS)
            
        if password is None:
            password = ESAPI.randomizer().get_random_string(8, DefaultEncoder.CHAR_ALPHANUMERICS)
            while True:
                try:
                    ESAPI.authenticator().verify_password_strength(password)
                except:
                    password = ESAPI.randomizer().get_random_string(8, DefaultEncoder.CHAR_ALPHANUMERICS)
                else:
                    break
            
        caller = inspect.stack()[2][3]
        print (_("Creating user %(username)s for %(caller)s") %
            {'username' : username,
             'caller' : caller})
        # Not sure if User tests should be coupled with Authenticator...
        user = ESAPI.authenticator().create_user(username, password, password)
        return user
        
    def test_add_role(self):
        user = self.create_test_user()
        role = "therole"
        user.add_role(role)
        self.assertTrue(user.is_in_role(role))
        self.assertFalse(user.is_in_role("ridiculous"))
        
        user.add_role(role)
        self.assertEquals(1, len(user.roles))
        
    def test_add_roles(self):
        user = self.create_test_user()
        roles = ['rolea', 'roleb']
        user.add_roles(roles)
        self.assertTrue(user.is_in_role('rolea'))
        self.assertTrue(user.is_in_role('roleb'))
        self.assertFalse(user.is_in_role('ridiculous'))
        
    def test_change_password(self):
        instance = ESAPI.authenticator()
        old_password = 'password12!@'
        user = self.create_test_user(password=old_password)
        print (_("Hash of %(old_password)s = %(hash)s") %
            {'old_password' : old_password,
             'hash' : instance.get_hashed_password(user)})
        
        password1 = "SomethingElse34#$"
        user.change_password(old_password, password1, password1)
        print (_("Hash of %(password)s = %(hash)s") %
            {'password' : password1,
             'hash' : instance.get_hashed_password(user)})
        self.assertTrue(user.verify_password(password1))
        self.assertFalse(user.verify_password(old_password))
        
        password2 = "YetAnother56%^"
        user.change_password(password1, password2, password2)
        print (_("Hash of %(password)s = %(hash)s") %
            {'password' : password2,
             'hash' : instance.get_hashed_password(user)})
        self.assertTrue(user.verify_password(password2))
        self.assertFalse(user.verify_password(password1))
        
        try: 
            user.change_password(password2, password1, password1)
            # Should not be able to re-use a password
            self.fail()
        except AuthenticationException:
            pass
            
        self.assertFalse(user.verify_password("badpass"))
     
    def test_enable_disable(self):
        user = self.create_test_user(password='password12!@')
        user.enable()
        self.assertTrue(user.is_enabled())
        user.disable()
        self.assertFalse(user.is_enabled())
        
    def test_failed_login_lockout(self):
        pass
    
    def test_account_name(self):
        user = self.create_test_user(username='testAccountNameUser')
        account_name = 'newname'
        user.account_name = account_name
        self.assertEquals(account_name, user.account_name)
        self.assertFalse("ridiculous" == user.account_name)
        
    def test_last_failed_login_time(self):
        user = self.create_test_user()
        
        try:
            user.login_with_password("ridiculous")
        except:
            pass
            
        time1 = user.last_failed_login_time
        time.sleep(0.01)
        try:
            user.login_with_password("ridiculous")
        except:
            pass

        time2 = user.last_failed_login_time
        self.assertFalse(time1 == time2)
        self.assertTrue(time1 < time2)
        
    def test_last_login_time(self):
        password = 'testpass12!@'
        user = self.create_test_user(password=password)
        user.verify_password(password)
        time1 = user.last_login_time
        time.sleep(0.01)
        user.verify_password(password)
        time2 = user.last_login_time
        self.assertTrue(time1 < time2)
        
    def test_last_password_change_time(self):
        old_password = 'password12!@'
        user = self.create_test_user(password=old_password)
        time1 = user.last_password_change_time
        time.sleep(0.01)
        new_password = 'woot23@#'
        user.change_password(old_password, new_password, new_password)
        time2 = user.last_password_change_time
        self.assertTrue(time1 < time2)
        
    def test_get_roles(self):
        user = self.create_test_user()
        role = 'admin'
        user.add_role(role)
        roles = user.roles
        self.assertTrue(len(roles) > 0)
        self.assertTrue(role in roles)
        
    def test_remove_role(self):
        user = self.create_test_user()
        role = 'therole'
        user.add_role(role)
        self.assertTrue(user.is_in_role(role))
        user.remove_role(role)
        self.assertFalse(user.is_in_role(role))
        
    def test_screen_name(self):
        user = self.create_test_user()
        screen_name = 'c00lk1d'
        user.screen_name = screen_name
        self.assertEquals(screen_name, user.screen_name)
        self.assertFalse('ridiculous' == user.screen_name)
        
    def test_get_sessions(self):
        pass
           
    def test_add_sessions(self):
        pass
        
    def test_remove_sessions(self):
        pass
        
    def test_increment_failed_login_count(self):
        user = self.create_test_user()
        user.enable()
        self.assertEquals(0, user.get_failed_login_count())
        
        self.assertRaises(AuthenticationLoginException, user.login_with_password, "ridiculous")
            
        self.assertEquals(1, user.get_failed_login_count())
        
        self.assertRaises(AuthenticationLoginException, user.login_with_password, "ridiculous")            
        self.assertEquals(2, user.get_failed_login_count())
        
    def test_is_enabled(self):
        user = self.create_test_user()
        user.disable()
        self.assertFalse(user.is_enabled())
        user.enable()
        self.assertTrue(user.is_enabled())
        
    def test_is_in_role(self):
        user = self.create_test_user()
        role = "testrole"
        self.assertFalse(user.is_in_role(role))
        user.add_role(role)
        self.assertTrue(user.is_in_role(role))
        self.assertFalse(user.is_in_role("ridiculous"))
        
    def test_set_roles(self):
        user = self.create_test_user()
        user.add_role('user')
        user.roles = ['rolea', 'roleb']
        self.assertFalse(user.is_in_role('user'))
        self.assertTrue(user.is_in_role('rolea'))
        self.assertTrue(user.is_in_role('roleb'))
        self.assertFalse(user.is_in_role('ridiculous'))
        
    def test_locking(self):
        user = self.create_test_user()
        user.lock()
        self.assertTrue(user.is_locked())
        user.unlock()
        self.assertFalse(user.is_locked())
        
    def test_is_session_absolute_timeout(self):
        pass
        
    def test_is_session_timeout(self):
        pass
        
    def test_login_with_password(self):
        password = 'password12!@'
        user = self.create_test_user(password=password)
        user.enable()
        user.login_with_password(password)
        self.assertTrue(user.is_logged_in())
        
        # Test no password
        user.logout()
        self.assertRaises(AuthenticationLoginException, user.login_with_password, None)
        
        # Test disabled
        user.logout()
        user.disable()
        self.assertRaises(AuthenticationLoginException, user.login_with_password, password)
        user.enable()
        
        # Test lockout
        user.logout()
        self.assertFalse(user.is_logged_in())
        self.assertFalse(user.is_locked())
        self.assertTrue(user.is_enabled())
        
        for i in range(15):
            try:
                user.login_with_password('wrongpassword')
            except:
                pass
            self.assertFalse(user.is_logged_in())
            
        self.assertTrue(user.is_locked())
        self.assertRaises(AuthenticationLoginException, user.login_with_password, password)
        user.unlock()
        self.assertEquals(user.failed_login_count, 0)
        
    def test_expired_user(self):
        password = "password12!@"
        user = self.create_test_user(password=password)
        user.enable()
        user.expiration_time = datetime.now() - timedelta(days=1)
        
        self.assertRaises(AuthenticationLoginException, user.login_with_password, password)
            
    def test_logout(self):
        password = 'password12!@'
        user = self.create_test_user(password=password)
        user.enable()
        user.login_with_password(password)
        self.assertTrue(user.is_logged_in())
        user.logout()
        self.assertFalse(user.is_logged_in())
        
    def test_reset_csrf(self):
        user = self.create_test_user()
        token1 = user.reset_csrf_token()
        token2 = user.reset_csrf_token()
        self.assertFalse(token1 == token2)
        
    def test_expiration_time(self):
        user = self.create_test_user()
        
        # Date in past, should expire
        user.expiration_time = datetime.min
        self.assertTrue( user.is_expired() )
        
        # Date in future, should not expire
        user.expiration_time = datetime.max
        self.assertFalse( user.is_expired() )
            def test_locale(self):
        user = self.create_test_user()
        locale = "en/US"
        user.locale = locale
        self.assertEquals(user.locale, locale)
           
if __name__ == "__main__":
    unittest.main()

