#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: Test suite for the Logger interface.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

# Use esapi/test/conf instead of esapi/conf
# It is important that this is at the top, as it affects the imports below
# by loading the test configuration instead of the normal one.
# This should ONLY ever be used in the unit tests.
import esapi.test.conf

import unittest
import sys
from Cookie import Morsel

from esapi.core import ESAPI
from esapi.http_utilities import HTTPUtilities

from esapi.test.http.mock_http_request import MockHttpRequest
from esapi.test.http.mock_http_response import MockHttpResponse
from esapi.test.http.mock_session import MockSession

class HTTPUtilitiesTest(unittest.TestCase): 
    def __init__(self, test_name=""):
        """
        Instantiates a new HTTPUtilities test.
        
        @param test_name: the test name
        """
        unittest.TestCase.__init__(self, test_name)
        
    def setUp(self):
        ESAPI.authenticator().clear_all_data()
    
    def test_csrf_token(self):
        username = "testCSRFUser"
        password = "addCSRFToken"
        user = ESAPI.authenticator().create_user(username, password, password)
        ESAPI.authenticator().current_user = user 
        token = ESAPI.http_utilities().get_csrf_token()
        self.assertEquals(8, len(token))
        request = MockHttpRequest()
        try:
            ESAPI.http_utilities().verify_csrf_token(request)
            self.fail()
        except:
            # expected
            pass
            
        request.GET[HTTPUtilities.CSRF_TOKEN_NAME] = token
        ESAPI.http_utilities().verify_csrf_token(request)
        
    def test_add_csrf_token(self):
        instance = ESAPI.authenticator()
        username = "addCSRFUser"
        password = 'addCSRFToken'
        user = instance.create_user(username, password, password)
        instance.current_user = user
        
        csrf1 = ESAPI.http_utilities().add_csrf_token('/test1')
        self.assertTrue(csrf1.find('?') > -1)
        
        csrf2 = ESAPI.http_utilities().add_csrf_token('test1?one=two')
        self.assertTrue(csrf2.find('?') > -1)
        
    def test_add_header(self):
        instance = ESAPI.http_utilities()
        request = MockHttpRequest()
        response = MockHttpResponse()
        instance.set_current_http(request, response)
        
        instance.add_header('HeaderName', 'HeaderValue')
        
    def test_assert_secure_request(self):
        request = MockHttpRequest()
        
        bad = ['http://example.com',
               'ftp://example.com',
               '',
               None,]
               
        good = ['https://example.com']
        
        for bad_url in bad: 
            try:
                request.url = bad_url
                ESAPI.http_utilities().assert_secure_request(request)
                self.fail()
            except:
                pass
            
        for good_url in good:
            try:
                request.url = good_url
                ESAPI.http_utilities().assert_secure_request(request)
            except:
                self.fail()
                
    def test_change_session_identifier(self):
        request = MockHttpRequest()
        response = MockHttpResponse()
        ESAPI.http_utilities().set_current_http(request, response)
        session = request.session
        session['one'] = 'one'
        session['two'] = 'two'
        session['three'] = 'three'
        id1 = request.session.id
        
        session = ESAPI.http_utilities().change_session_identifier(request)
        id2 = request.session.id
            
        self.assertFalse(id1 == id2)
        self.assertEquals("one", session['one'])
        
    def test_kill_cookie(self):
        request = MockHttpRequest()
        response = MockHttpResponse()
        
        ESAPI.http_utilities().set_current_http(request, response)
        self.assertTrue(len(response.cookies) == 0)
        
        new_cookies = {}
        m = Morsel()
        m.key = 'test1'
        m.value = '1'
        new_cookies[m.key] = m
        
        m = Morsel()
        m.key = 'test2'
        m.value = '2'
        new_cookies[m.key] = m
        
        request.cookies = new_cookies
        ESAPI.http_utilities().kill_cookie( "test1", request, response )
        self.assertTrue(len(response.cookies) == 1)
        
    def test_send_safe_redirect(self):
        pass
        
    def test_add_cookie(self):
        instance = ESAPI.http_utilities()
        response = MockHttpResponse()
        request = MockHttpRequest()
        instance.set_current_http(request, response)
        self.assertEquals(0, len(response.cookies))
        
        # add_cookie(key, value='', max_age=None, path='/', domain=None,
        # secure=None, httponly=False, version=None, comment=None, expires=None)

        instance.add_cookie(response, key='test1', value='test1')
        self.assertEquals(1, len(response.cookies))
        
        instance.add_cookie(key='test2', value='test2')
        self.assertEquals(2, len(response.cookies))
        
        # illegal name
        instance.add_cookie(response, key='tes<t3', value='test3')
        self.assertEquals(2, len(response.cookies))
        
        # illegal value
        instance.add_cookie(response, key='test3', value='tes<t3')
        self.assertEquals(2, len(response.cookies))
        
    def test_state_from_encrypted_cookie(self):
        request = MockHttpRequest()
        response = MockHttpResponse()
        
        empty = ESAPI.http_utilities().decrypt_state_from_cookie(request)
        self.assertEquals({}, empty)
        
        m = {'one' : 'aspect',
             'two' : 'ridiculous',
             'test_hard' : "&(@#*!^|;,." }
             
        ESAPI.http_utilities().encrypt_state_in_cookie(m, response)
        value = response.headers['Set-Cookie']
        encrypted = value[value.find('=')+1:value.find(';')]
        ESAPI.encryptor().decrypt(encrypted)
            
    def test_save_too_long_state_in_cookie(self):
        request = MockHttpRequest()
        response = MockHttpResponse()
        ESAPI.http_utilities().set_current_http(request, response)
        
        foo = "abcd" * 1000
        
        data = {'long': foo}
        try:
            ESAPI.http_utilities().encrypt_state_in_cookie(response, data)
            self.fail()
        except:
            pass
            
    def test_set_no_cache_headers(self):
        request = MockHttpRequest()
        response = MockHttpResponse()
        ESAPI.http_utilities().set_current_http(request, response)
        self.assertEquals(0, len(response.headers))
        
        response.headers["test1"] = "1"
        response.headers["test2"] = "2"
        response.headers["test3"] = "3"
        
        self.assertEquals(3, len(response.headers))
        ESAPI.http_utilities().set_no_cache_headers( response )
        self.assertTrue(response.headers.has_key('Cache-Control'))
        self.assertTrue(response.headers.has_key('Expires'))
        
    def test_set_remember_token(self):
        instance = ESAPI.authenticator()
        
        account_name = "joestheplumber"
        password = instance.generate_strong_password()
        user = instance.create_user(account_name, password, password)
        user.enable()
        request = MockHttpRequest()
        request.POST['username'] = account_name
        request.POST['password'] = password
        response = MockHttpResponse()
        instance.login(request, response)
        
        max_age = 60 * 60 * 24 * 14
        ESAPI.http_utilities().set_remember_token( password, max_age, "domain", '/', request, response )
        
    def test_query_to_dict(self):
        instance = ESAPI.http_utilities()
        
        query = '?a=1&b=2&c=3'
        testing = instance.query_to_dict(query)
        correct = {'a' : '1', 'b' : '2', 'c' : '3'}
        self.assertEquals(testing, correct)
        
if __name__ == "__main__":
    unittest.main()
