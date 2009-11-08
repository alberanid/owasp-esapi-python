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

from esapi.core import ESAPI
from esapi.logger import Logger

class LoggerTest(unittest.TestCase): 
    test_count = 0
    
    def __init__(self, test_name=""):
        """
        Instantiates a new Logger test.
        
        @param test_name: the test name
        """
        unittest.TestCase.__init__(self, test_name)
        self.test_logger = None
    
    def setUp(self):
        self.test_logger = ESAPI.logger("test" + str(LoggerTest.test_count))
        LoggerTest.test_count += 1
        
        print "Test Logger: " + str(self.test_logger)
        
    def tearDown(self):
        self.test_logger = None
        
    def runTest(self):
        assert self.test_logger.test() == True
    
#    def testLogHTTPRequest(self):
#        """
#        Test of logHTTPRequest method, of class org.owasp.esapi.ESAPI.Logger.
#        
#        @throws ValidationException
#                    the validation exception
#        @throws IOException
#                    Signals that an I/O exception has occurred.
#        @throws AuthenticationException
#                    the authentication exception
#        """
#        print "logHTTPRequest"
#        ignore = ["password", "ssn", "ccn"]
#        request = MockHttpServletRequest()
#        response = MockHttpServletResponse()
#        esapi.ESAPI.httpUtilities().setCurrentHTTP(request, response)
#        Logger = esapi.ESAPI.getLogger("Logger")
#        esapi.ESAPI.httpUtilities().logHTTPRequest(request, Logger, ignore)
#        request.addParameter("one","one")
#        request.addParameter("two","two1")
#        request.addParameter("two","two2")
#        request.addParameter("password","jwilliams")
#        esapi.ESAPI.httpUtilities().logHTTPRequest(request, Logger, ignore)
    
    def test_set_level(self):
        """
        Test of set_level method of the inner class 
        esapi.reference.PythonLogger that is defined in 
        esapi.reference.PythonLogFactory.
        """
        
        # First, test all the different logging levels
        
        self.test_logger.set_level( Logger.ALL )
        self.assertTrue(self.test_logger.is_fatal_enabled())
        self.assertTrue(self.test_logger.is_error_enabled())
        self.assertTrue(self.test_logger.is_warning_enabled())
        self.assertTrue(self.test_logger.is_info_enabled())
        self.assertTrue(self.test_logger.is_debug_enabled())
        self.assertTrue(self.test_logger.is_trace_enabled())

        self.test_logger.set_level( Logger.TRACE )
        self.assertTrue(self.test_logger.is_fatal_enabled())
        self.assertTrue(self.test_logger.is_error_enabled())
        self.assertTrue(self.test_logger.is_warning_enabled())
        self.assertTrue(self.test_logger.is_info_enabled())
        self.assertTrue(self.test_logger.is_debug_enabled())
        self.assertTrue(self.test_logger.is_trace_enabled())
        
        self.test_logger.set_level( Logger.DEBUG )
        self.assertTrue(self.test_logger.is_fatal_enabled())
        self.assertTrue(self.test_logger.is_error_enabled())
        self.assertTrue(self.test_logger.is_warning_enabled())
        self.assertTrue(self.test_logger.is_info_enabled())
        self.assertTrue(self.test_logger.is_debug_enabled())
        self.assertFalse(self.test_logger.is_trace_enabled())
        
        self.test_logger.set_level( Logger.INFO )
        self.assertTrue(self.test_logger.is_fatal_enabled())
        self.assertTrue(self.test_logger.is_error_enabled())
        self.assertTrue(self.test_logger.is_warning_enabled())
        self.assertTrue(self.test_logger.is_info_enabled())
        self.assertFalse(self.test_logger.is_debug_enabled())
        self.assertFalse(self.test_logger.is_trace_enabled())
        
        self.test_logger.set_level( Logger.WARNING )
        self.assertTrue(self.test_logger.is_fatal_enabled())
        self.assertTrue(self.test_logger.is_error_enabled())
        self.assertTrue(self.test_logger.is_warning_enabled())
        self.assertFalse(self.test_logger.is_info_enabled())
        self.assertFalse(self.test_logger.is_debug_enabled())
        self.assertFalse(self.test_logger.is_trace_enabled())
        
        self.test_logger.set_level( Logger.ERROR )
        self.assertTrue(self.test_logger.is_fatal_enabled())
        self.assertTrue(self.test_logger.is_error_enabled())
        self.assertFalse(self.test_logger.is_warning_enabled())
        self.assertFalse(self.test_logger.is_info_enabled())
        self.assertFalse(self.test_logger.is_debug_enabled())
        self.assertFalse(self.test_logger.is_trace_enabled())
        
        self.test_logger.set_level( Logger.FATAL )
        self.assertTrue(self.test_logger.is_fatal_enabled())
        self.assertFalse(self.test_logger.is_error_enabled())
        self.assertFalse(self.test_logger.is_warning_enabled())
        self.assertFalse(self.test_logger.is_info_enabled())
        self.assertFalse(self.test_logger.is_debug_enabled())
        self.assertFalse(self.test_logger.is_trace_enabled())
        
        self.test_logger.set_level( Logger.OFF )
        self.assertFalse(self.test_logger.is_fatal_enabled())
        self.assertFalse(self.test_logger.is_error_enabled())
        self.assertFalse(self.test_logger.is_warning_enabled())
        self.assertFalse(self.test_logger.is_info_enabled())
        self.assertFalse(self.test_logger.is_debug_enabled())
        self.assertFalse(self.test_logger.is_trace_enabled())
        
        # Now test to see if a change to the logging level in one log affects other logs
        new_logger = ESAPI.logger("test_num2" )
        self.test_logger.set_level( Logger.OFF )
        new_logger.set_level( Logger.INFO )
        self.assertFalse(self.test_logger.is_fatal_enabled())
        self.assertFalse(self.test_logger.is_error_enabled())
        self.assertFalse(self.test_logger.is_warning_enabled())
        self.assertFalse(self.test_logger.is_info_enabled())
        self.assertFalse(self.test_logger.is_debug_enabled())
        self.assertFalse(self.test_logger.is_trace_enabled())
        
        self.assertTrue(new_logger.is_fatal_enabled())
        self.assertTrue(new_logger.is_error_enabled())
        self.assertTrue(new_logger.is_warning_enabled())
        self.assertTrue(new_logger.is_info_enabled())
        self.assertFalse(new_logger.is_debug_enabled())
        self.assertFalse(new_logger.is_trace_enabled())
        
    def test_info(self):
        """
        Test of info method, of class esapi.Logger.
        """
        self.test_logger.info(Logger.SECURITY_SUCCESS, "test message")
        self.test_logger.info(Logger.SECURITY_SUCCESS, "test message", None)
        self.test_logger.info(Logger.SECURITY_SUCCESS, "%3escript%3f test message", None)
        self.test_logger.info(Logger.SECURITY_SUCCESS, "<script> test message", None)
        
    def test_trace(self):
        """
        Test of trace method, of class esapi.Logger.
        """
        self.test_logger.trace(Logger.SECURITY_SUCCESS, "test message trace")
        self.test_logger.trace(Logger.SECURITY_SUCCESS, "test message trace", None)
        
    def test_debug(self):
        """
        Test of debug method, of class esapi.Logger.
        """
        self.test_logger.debug(Logger.SECURITY_SUCCESS, "test message debug")
        self.test_logger.debug(Logger.SECURITY_SUCCESS, "test message debug", None)
        
    def test_error(self):
        """
        Test of error method, of class esapi.Logger.
        """
        self.test_logger.error(Logger.SECURITY_SUCCESS, "test message error")
        self.test_logger.error(Logger.SECURITY_SUCCESS, "test message error", None)

    def test_warning(self):
        """
        Test of warning method, of class esapi.Logger.
        """
        self.test_logger.warning(Logger.SECURITY_SUCCESS, "test message warning")
        self.test_logger.warning(Logger.SECURITY_SUCCESS, "test message warning", None)
    
    def test_fatal(self):
        """
        Test of fatal method, of class esapi.Logger.
        """
        self.test_logger.fatal(Logger.SECURITY_SUCCESS, "test message fatal")
        self.test_logger.fatal(Logger.SECURITY_SUCCESS, "test message fatal", None)

    
if __name__ == "__main__":
    unittest.main()

