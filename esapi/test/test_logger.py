"""
OWASP Enterprise Security API (ESAPI)
 
This file is part of the Open Web Application Security Project (OWASP)
Enterprise Security API (ESAPI) project. For details, please see
<a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
Copyright (c) 2009 - The OWASP Foundation

The ESAPI is published by OWASP under the BSD license. You should read and accept the
LICENSE before you use, modify, and/or redistribute this software.

@author Craig Younkins (craig.younkins@owasp.org)
"""

import unittest
import sys

import esapi.core as core
from esapi.logger import Logger

class LoggerTest(unittest.TestCase):
    """
    The Class LoggerTest
    
    @author Craig Younkins (craig.younkins@owasp.org)
    """
    
    testCount = 0
    
    def __init__(self, testName=""):
        """
        Instantiates a new Logger test.
        
        @param testName the test name
        """
        unittest.TestCase.__init__(self, testName)
        self.testLogger = None
    
    def setUp(self):
        self.testLogger = core.getLogger("test" + str(LoggerTest.testCount))
        LoggerTest.testCount += 1
        
        print "Test Logger: " + str(self.testLogger)
        
    def tearDown(self):
        self.testLogger = None
        
    def runTest(self):
        assert self.testLogger.test() == True
        
    def suite(self):
        """
        Suite.
        
        @return the test
        """
        suite = unittest.makeSuite(Logger,'test')
        
        return suite
    
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
    
    def testSetLevel(self):
        """
        Test of setLevel method of the inner class esapi.reference.PythonLogger that is defined in 
        esapi.reference.PythonLogFactory.
        """
        
        # First, test all the different logging levels
        
        self.testLogger.setLevel( Logger.ALL )
        self.assertTrue(self.testLogger.isFatalEnabled())
        self.assertTrue(self.testLogger.isErrorEnabled())
        self.assertTrue(self.testLogger.isWarningEnabled())
        self.assertTrue(self.testLogger.isInfoEnabled())
        self.assertTrue(self.testLogger.isDebugEnabled())
        self.assertTrue(self.testLogger.isTraceEnabled())

        self.testLogger.setLevel( Logger.TRACE )
        self.assertTrue(self.testLogger.isFatalEnabled())
        self.assertTrue(self.testLogger.isErrorEnabled())
        self.assertTrue(self.testLogger.isWarningEnabled())
        self.assertTrue(self.testLogger.isInfoEnabled())
        self.assertTrue(self.testLogger.isDebugEnabled())
        self.assertTrue(self.testLogger.isTraceEnabled())
        
        self.testLogger.setLevel( Logger.DEBUG )
        self.assertTrue(self.testLogger.isFatalEnabled())
        self.assertTrue(self.testLogger.isErrorEnabled())
        self.assertTrue(self.testLogger.isWarningEnabled())
        self.assertTrue(self.testLogger.isInfoEnabled())
        self.assertTrue(self.testLogger.isDebugEnabled())
        self.assertFalse(self.testLogger.isTraceEnabled())
        
        self.testLogger.setLevel( Logger.INFO )
        self.assertTrue(self.testLogger.isFatalEnabled())
        self.assertTrue(self.testLogger.isErrorEnabled())
        self.assertTrue(self.testLogger.isWarningEnabled())
        self.assertTrue(self.testLogger.isInfoEnabled())
        self.assertFalse(self.testLogger.isDebugEnabled())
        self.assertFalse(self.testLogger.isTraceEnabled())
        
        self.testLogger.setLevel( Logger.WARNING )
        self.assertTrue(self.testLogger.isFatalEnabled())
        self.assertTrue(self.testLogger.isErrorEnabled())
        self.assertTrue(self.testLogger.isWarningEnabled())
        self.assertFalse(self.testLogger.isInfoEnabled())
        self.assertFalse(self.testLogger.isDebugEnabled())
        self.assertFalse(self.testLogger.isTraceEnabled())
        
        self.testLogger.setLevel( Logger.ERROR )
        self.assertTrue(self.testLogger.isFatalEnabled())
        self.assertTrue(self.testLogger.isErrorEnabled())
        self.assertFalse(self.testLogger.isWarningEnabled())
        self.assertFalse(self.testLogger.isInfoEnabled())
        self.assertFalse(self.testLogger.isDebugEnabled())
        self.assertFalse(self.testLogger.isTraceEnabled())
        
        self.testLogger.setLevel( Logger.FATAL )
        self.assertTrue(self.testLogger.isFatalEnabled())
        self.assertFalse(self.testLogger.isErrorEnabled())
        self.assertFalse(self.testLogger.isWarningEnabled())
        self.assertFalse(self.testLogger.isInfoEnabled())
        self.assertFalse(self.testLogger.isDebugEnabled())
        self.assertFalse(self.testLogger.isTraceEnabled())
        
        self.testLogger.setLevel( Logger.OFF )
        self.assertFalse(self.testLogger.isFatalEnabled())
        self.assertFalse(self.testLogger.isErrorEnabled())
        self.assertFalse(self.testLogger.isWarningEnabled())
        self.assertFalse(self.testLogger.isInfoEnabled())
        self.assertFalse(self.testLogger.isDebugEnabled())
        self.assertFalse(self.testLogger.isTraceEnabled())
        
        # Now test to see if a change to the logging level in one log affects other logs
        newLogger = core.getLogger("test_num2" )
        self.testLogger.setLevel( Logger.OFF )
        newLogger.setLevel( Logger.INFO )
        self.assertFalse(self.testLogger.isFatalEnabled())
        self.assertFalse(self.testLogger.isErrorEnabled())
        self.assertFalse(self.testLogger.isWarningEnabled())
        self.assertFalse(self.testLogger.isInfoEnabled())
        self.assertFalse(self.testLogger.isDebugEnabled())
        self.assertFalse(self.testLogger.isTraceEnabled())
        
        self.assertTrue(newLogger.isFatalEnabled())
        self.assertTrue(newLogger.isErrorEnabled())
        self.assertTrue(newLogger.isWarningEnabled())
        self.assertTrue(newLogger.isInfoEnabled())
        self.assertFalse(newLogger.isDebugEnabled())
        self.assertFalse(newLogger.isTraceEnabled())
        
    def testInfo(self):
        """
        Test of info method, of class esapi.Logger.
        """
        self.testLogger.info(Logger.SECURITY_SUCCESS, "test message")
        self.testLogger.info(Logger.SECURITY_SUCCESS, "test message", None)
        self.testLogger.info(Logger.SECURITY_SUCCESS, "%3escript%3f test message", None)
        self.testLogger.info(Logger.SECURITY_SUCCESS, "<script> test message", None)
        
    def testTrace(self):
        """
        Test of trace method, of class esapi.Logger.
        """
        self.testLogger.trace(Logger.SECURITY_SUCCESS, "test message trace")
        self.testLogger.trace(Logger.SECURITY_SUCCESS, "test message trace", None)
        
    def testDebug(self):
        """
        Test of debug method, of class esapi.Logger.
        """
        self.testLogger.debug(Logger.SECURITY_SUCCESS, "test message debug")
        self.testLogger.debug(Logger.SECURITY_SUCCESS, "test message debug", None)
        
    def testError(self):
        """
        Test of error method, of class esapi.Logger.
        """
        self.testLogger.error(Logger.SECURITY_SUCCESS, "test message error")
        self.testLogger.error(Logger.SECURITY_SUCCESS, "test message error", None)

    def testWarning(self):
        """
        Test of warning method, of class esapi.Logger.
        """
        self.testLogger.warning(Logger.SECURITY_SUCCESS, "test message warning")
        self.testLogger.warning(Logger.SECURITY_SUCCESS, "test message warning", None)
    
    def testFatal(self):
        """
        Test of fatal method, of class esapi.Logger.
        """
        self.testLogger.fatal(Logger.SECURITY_SUCCESS, "test message fatal")
        self.testLogger.fatal(Logger.SECURITY_SUCCESS, "test message fatal", None)

    
if __name__ == "__main__":
    unittest.main()

