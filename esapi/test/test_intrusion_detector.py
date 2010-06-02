#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: Test suite for IntrusionDetector interface.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

# Use esapi/test/conf instead of esapi/conf
# It is important that this is at the top, as it affects the imports below
# by loading the test configuration instead of the normal one.
# This should ONLY ever be used in the unit tests.
import esapi.test.conf

import unittest

from esapi.core import ESAPI
from esapi.encoder import Encoder
from esapi.exceptions import AuthenticationException, ValidationException, IntegrityException, IntrusionException
from esapi.test.http.mock_http_request import MockHttpRequest
from esapi.test.http.mock_http_response import MockHttpResponse

class IntrusionDetectorTest(unittest.TestCase):
    def __init__(self, test_name=""):
        unittest.TestCase.__init__(self, test_name)
        
    def setUp(self):
        ESAPI.authenticator().clear_all_data()
        
    def test_add_exception(self):
        ESAPI.intrusion_detector().add_exception( RuntimeError('message') )
        ESAPI.intrusion_detector().add_exception( 
            ValidationException("user message", "log message") )
        ESAPI.intrusion_detector().add_exception( 
            IntrusionException("user message", "log message") )
            
        username = "testAddException"
        password = "addException"
        auth = ESAPI.authenticator()
        user = auth.create_user(username, password, password)
        user.enable()
        
        request = MockHttpRequest()
        response = MockHttpResponse()
        ESAPI.http_utilities().set_current_http(request, response)
        user.login_with_password(password)
        
        # Generate some exceptions to disable the account
        for i in range(15):
            IntegrityException(
                "IntegrityException %s" % i,
                "IntegrityException %s" % i )
            
        self.assertFalse(user.is_logged_in())
        self.assertTrue(user.is_locked())
        
    def test_add_event(self):
        username = "testAddEventIDS"
        password = "addEvent"
        auth = ESAPI.authenticator()
        user = auth.create_user(username, password, password)
        user.enable()
        
        request = MockHttpRequest()
        response = MockHttpResponse()
        ESAPI.http_utilities().set_current_http(request, response)
        user.login_with_password(password)
        
        # Generate some events to disable the account
        for i in range(15):
            ESAPI.intrusion_detector().add_event("test", "test message")
            
        self.assertTrue(user.is_locked())
        
if __name__ == "__main__":
    unittest.main()
