#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: Test suite for Authenticator interface.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

# Use esapi/test/conf instead of esapi/conf
# It is important that this is at the top, as it affects the imports below
# by loading the test configuration instead of the normal one.
# This should ONLY ever be used in the unit tests.
import esapi.test.conf

import unittest
import os
import os.path
from datetime import datetime, timedelta
from Cookie import Morsel

from esapi.core import ESAPI
from esapi.exceptions import AuthenticationException
from esapi.http_utilities import HTTPUtilities
from esapi.test.http.mock_http_request import MockHttpRequest
from esapi.test.http.mock_http_response import MockHttpResponse

# A test should be added to test the thread safety

class ValidatorTest(unittest.TestCase):
    def __init__(self, test_name=""):
        unittest.TestCase.__init__(self, test_name)
        
    def setUp(self):
        request = MockHttpRequest()
        response = MockHttpResponse()
        ESAPI.http_utilities().set_current_http(request, response)
        ESAPI.authenticator().logout()
        ESAPI.authenticator().clear_all_data()
        
    def test_create_user(self):
        instance = ESAPI.authenticator()
        account_name = "awesomebob"
        password = "a1b2c3d4e5f6g7h8"
        user = instance.create_user(account_name, password, password)
        
        # duplicate user
        self.assertRaises(AuthenticationException, instance.create_user, account_name, 
            password, password)
        
        # passwords don't match
        self.assertRaises(AuthenticationException, instance.create_user, "nonmatchuser",
            "a1b2c3d4e5f6g7h8", "z1b2c3d4e5f6g7h8")
            
        # Weak password
        self.assertRaises(AuthenticationException, instance.create_user, "weakuser",
            "weak1", "weak1")
            
        # None username
        self.assertRaises(AuthenticationException, instance.create_user, None,
            "comPl3xPass", "comPl3xPass")
            
        # None password
        self.assertRaises(AuthenticationException, instance.create_user, "nopassword", 
            None, None)
            
    def test_verify_password(self):
        instance = ESAPI.authenticator()
        account_name = "awesomebob"
        password = "a1b2c3d4e5f6g7h8"
        user = instance.create_user(account_name, password, password)
        self.assertTrue(user.verify_password(password))

    def test_generate_strong_password(self):
        instance = ESAPI.authenticator()
        old_password = 'iiiiiiiiiii'
        for i in range(100):
            try:
                new_password = instance.generate_strong_password()
                instance.verify_password_strength(new_password, old_password)
            except AuthenticationException, extra:
                print "FAILED >> " + new_password
                raise
                
    def test_verify_password_strength(self):
        instance = ESAPI.authenticator()
        
        # Should catch the same middle part
        self.assertRaises(AuthenticationException, instance.verify_password_strength,
            "test56^$test", "abcdx56^$sl" )
            
        # Complexity
        self.assertRaises(AuthenticationException, instance.verify_password_strength,
            "jeff" )
        
        # Complexity
        self.assertRaises(AuthenticationException, instance.verify_password_strength,
            "JEFF" )
            
        # Complexity
        self.assertRaises(AuthenticationException, instance.verify_password_strength,
            "1234" )
            
        # Same
        self.assertRaises(AuthenticationException, instance.verify_password_strength,
            "password" )
            
        # Weak
        self.assertRaises(AuthenticationException, instance.verify_password_strength,
            "-1" )
            
        # Weak
        #self.assertRaises(AuthenticationException, instance.verify_password_strength,
#            "password123" )
            
        # Weak
        self.assertRaises(AuthenticationException, instance.verify_password_strength,
            "test123" )
            
        # Passes
        instance.verify_password_strength("jeffJEFF12!")
        instance.verify_password_strength("super calif ragil istic")
        instance.verify_password_strength("TONYTONYTONYTONY")
        instance.verify_password_strength(instance.generate_strong_password())
            
    def test_current_user(self):
        instance = ESAPI.authenticator()
        
        username1 = "awesomeAlice"
        username2 = "awesomeBob"
        password = "getCurrentUser"
        
        user1 = instance.create_user(username1, password, password)
        user2 = instance.create_user(username2, password, password)
        
        user1.enable()
        
        request = MockHttpRequest()
        response = MockHttpResponse()
        
        ESAPI.http_utilities().set_current_http(request, response)
        user1.login_with_password(password)
        current_user = instance.current_user
        self.assertEquals(user1, current_user)
        instance.current_user = user2
        self.assertFalse( current_user.account_name == user2.account_name )
        
    def test_get_user(self):
        instance = ESAPI.authenticator()
        account_name = "testGetUser"
        password = "a1b2c3d4e5f6g7h8"
        instance.create_user(account_name, password, password)
        self.assertTrue( instance.get_user(account_name) )
        self.assertFalse( instance.get_user("ridiculous") )
        
    def test_get_user_from_token(self):
        instance = ESAPI.authenticator()
        instance.logout()
        
        account_name = "testUserFromToken"
        password = instance.generate_strong_password()
        user = instance.create_user(account_name, password, password)
        user.enable()
        
        ###
        request = MockHttpRequest()
        response = MockHttpResponse()
        ESAPI.http_utilities().set_current_http(request, response)
        
        m = Morsel()
        m.key = HTTPUtilities.REMEMBER_TOKEN_COOKIE_NAME
        m.value = "ridiculous"
        request.cookies[m.key] = m
        # Wrong cookie should fail
        self.assertRaises(AuthenticationException, instance.login, request, response)
        user.logout()
        ###
        
        request = MockHttpRequest()
        response = MockHttpResponse()
        ESAPI.authenticator().current_user = user
        new_token = ESAPI.http_utilities().set_remember_token(
            password, 10000, "test.com", request.path, request, response )
        request.set_cookie( key=HTTPUtilities.REMEMBER_TOKEN_COOKIE_NAME, value=new_token )
        ESAPI.http_utilities().set_current_http(request, response)
        
        # Logout the current user so we can log them in with the remember cookie
        user2 = instance.login(request, response)
        self.assertEquals(user, user2)
        
    def test_get_user_from_session(self):
        instance = ESAPI.authenticator()
        instance.logout()
        account_name = "sessionTester"
        password = instance.generate_strong_password()
        user = instance.create_user( account_name, password, password )
        user.enable()
        
        request = MockHttpRequest()
        request.POST['username'] = account_name
        request.POST['password'] = password
        
        response = MockHttpResponse()
        ESAPI.http_utilities().set_current_http( request, response )
        instance.login( request, response )
        current_user = instance.get_user_from_session()
        self.assertEquals(user, current_user)
       
    def test_hash_password(self):
        instance = ESAPI.authenticator()
        username = "Jeff"
        password = "test"
        result1 = instance.hash_password(password, username)
        result2 = instance.hash_password(password, username)
        self.assertEquals(result1, result2)
        
    def test_login(self):
        instance = ESAPI.authenticator()
        username = "testLoginUser"
        password = instance.generate_strong_password()
        user = instance.create_user(username, password, password)
        user.enable()
        
        request = MockHttpRequest()
        request.POST['username'] = username
        request.POST['password'] = password
        
        response = MockHttpResponse()
        test = instance.login( request, response )
        self.assertTrue( test.is_logged_in() )
        
    def test_remove_user(self):
        instance = ESAPI.authenticator()
        instance.logout()
        account_name = "testRemoveUser"
        password = instance.generate_strong_password()
        instance.create_user( account_name, password, password )
        self.assertTrue( instance.exists(account_name) )
        instance.remove_user(account_name)
        self.assertFalse( instance.exists(account_name) )
        
    def test_current_user(self):
        instance = ESAPI.authenticator()
        instance.logout()
        user1_name = "currentUser1"
        user2_name = "currentUser2"
        password = "getCurrentUser"
        user1 = instance.create_user(user1_name, password, password)
        user1.enable()
        
        request = MockHttpRequest()
        response = MockHttpResponse()
        ESAPI.http_utilities().set_current_http(request, response)
        user1.login_with_password(password)
        current_user = instance.current_user
        self.assertEquals(user1, current_user)
        
        user2 = instance.create_user(user2_name, password, password)
        instance.current_user = user2 
        self.assertFalse( current_user.account_name == user2.account_name )
        
    def test_set_current_user_with_request(self):
        instance = ESAPI.authenticator()
        instance.logout()
        
        account_name = "curUserWReq"
        password = instance.generate_strong_password()
        user = instance.create_user( account_name, password, password )
        user.enable()
        
        request = MockHttpRequest()
        request.POST['username'] = account_name
        request.POST['password'] = password
        
        response = MockHttpResponse()
        instance.login( request, response )
        self.assertEquals( user, instance.current_user )
        
        try:
            user.disable()
            instance.login( request, response )
            self.fail()
        except Exception:
            pass
        
        try:
            user.enable()
            user.lock()
            instance.login( request, response )
            self.fail()
        except Exception:
            pass
            
        try:
            use.unlock()
            user.expiration_time = datetime.now()
            instance.login(request, response)
        except Exception:
            pass
            
    def test_exists(self):
        instance = ESAPI.authenticator()
        account_name = "testExists"
        password = instance.generate_strong_password()
        instance.create_user( account_name, password, password )
        self.assertTrue(instance.exists(account_name))
        instance.remove_user(account_name)
        self.assertFalse(instance.exists(account_name))
            
if __name__ == "__main__":
    unittest.main()
