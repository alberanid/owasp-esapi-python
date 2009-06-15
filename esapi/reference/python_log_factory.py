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

# Todo: 
# Add HTTP Session info to log method
# Change log method after Authenticator has been written
# Change log method after HTML Encoder are written

import logging

import esapi.core
from esapi.log_factory import LogFactory
from esapi.logger import Logger
from esapi.translation import _

class PythonLogFactory(LogFactory):
    """
    Reference implementation of the LogFactory and Logger interfaces. This implementation uses the Python logging package, and marks each
    log message with the currently logged in user and the word "SECURITY" for security related events. 
    
    @author Craig Younkins (craig.younkins@owasp.org)
    @since June 1, 2009
    @see esapi.log_factory
    @see esapi.reference.python_log_factory.PythonLogFactory.PythonLogger
    """
    
    applicationName = None
    loggersMap = {}
    
    def __init__(self, applicationName=None):
        """
        Constructor for this implementation of the LogFactory interface.
        
        @param applicationName The name of the application this logger is being constructed for.
        """
        self.applicationName = applicationName
        
    def setApplicationName(self, applicationName):
        self.applicationName = applicationName
        
    def getLogger(self, classOrModule):
        if not self.loggersMap.has_key(classOrModule):
            self.loggersMap[classOrModule] = self.PythonLogger(self.applicationName, classOrModule)
            
        return self.loggersMap[classOrModule]
    
    class PythonLogger(Logger):
        """
        Reference implementation of the Logger interface.
        
        It implements most of the recommendations defined in the Logger interface description. It does not
        filter out any sensitive data specific to the current application or organization, such as credit
        cards, social security numbers, etc.
        
        @author Craig Younkins (craig.younkins@owasp.org)
        @since June 1, 2009
        @see esapi.LogFactory
        """
               
        # The logging object used by this class to log everything.
        pyLogger = None
        
        # The application name using this log.
        applicationName = None
        
        # The module name using this log.
        moduleName = None
        
        def __init__(self, applicationName, moduleName):
            """
            Public constructor should only ever be called via the appropriate LogFactory
            
            @param applicationName the application name
            @param moduleName the module name
            """
            self.applicationName = applicationName
            self.moduleName = moduleName
            
            # Set the log levels. These are straight from Logger.py
            logging.addLevelName(Logger.OFF, "OFF")
            logging.addLevelName(Logger.FATAL, "FATAL")
            logging.addLevelName(Logger.ERROR, "ERROR")
            logging.addLevelName(Logger.WARNING, "WARNING")
            logging.addLevelName(Logger.INFO, "INFO")
            logging.addLevelName(Logger.DEBUG, "DEBUG")
            logging.addLevelName(Logger.TRACE, "TRACE")
            logging.addLevelName(Logger.ALL, "ALL")
            
            # Make our logger
            self.pyLogger = logging.getLogger(applicationName + "." + moduleName)
            
            # create console handler and set level to debug
            ch = logging.StreamHandler()
            ch.setLevel(Logger.ALL)
            # create formatter
            formatter = logging.Formatter("%(levelname)s %(name)s - %(eventType)s - %(user)s@%(hostname)s:%(sessionID)s -- %(message)s")
            # add formatter to ch
            ch.setFormatter(formatter)
            # add ch to logger
            self.pyLogger.addHandler(ch)

        def setLevel(self, level):
            """
            Note: In this implementation, this change is not persistent,
            meaning that if the application is restarted, the log level will revert to the level defined in the
            ESAPI SecurityConfiguration properties file.
            """
            self.pyLogger.setLevel(level)
            
        def trace(self, type, message, exception=None):
            self.log(Logger.TRACE, type, message, exception)
            
        def debug(self, type, message, exception=None):
            self.log(Logger.DEBUG, type, message, exception)
            
        def info(self, type, message, exception=None):
            self.log(Logger.INFO, type, message, exception)
            
        def warning(self, type, message, exception=None):
            self.log(Logger.WARNING, type, message, exception)
            
        def error(self, type, message, exception=None):
            self.log(Logger.ERROR, type, message, exception)
            
        def fatal(self, type, message, exception=None):
            self.log(Logger.FATAL, type, message, exception)
            
        def log(self, level, type, message, exception):
            """
            Log the message after optionally encoding any special characters that might be dangerous when viewed
            by an HTML based log viewer. Also encode any carriage returns and line feeds to prevent log
            injection attacks. This logs all the supplied parameters plus the user ID, user's source IP, a logging
            specific session ID, and the current date/time.
            
            It will only log the message if the current logging level is enabled, otherwise it will
            discard the message.
            
            @param level the severity level of the security event
            @param type the type of the event (SECURITY, FUNCTIONALITY, etc.)
            @param message the message
            @param exception an exception
            """
            # Before we waste all kinds of time preparing this event for the log, let check to see if its loggable
            if not self.pyLogger.isEnabledFor(level): return
            
            #user = ESAPI.authenticator().getCurrentUser()
            
            # create a random session number for the user to represent the user's 'session', if it doesn't exist already
            userSessionIDforLogging = _("unknown")
            
            # Add HTTP Session information here
            
            # ensure there's something to log
            if message is None:
                message = ""
                
            # ensure no CRLF injection into logs for forging records
            clean = message.replace('\n', '_').replace('\r', '_')
            if esapi.core.getSecurityConfiguration().getLogEncodingRequired():
                clean = esapi.core.encoder().encodeForHTML(message)
                if message != clean:
                    clean += " (Encoded)"
                      
            extra = {
                 'eventType' : str(type),
                 'eventSuccess' : [_("SUCCESS"),_("FAILURE")][type.isSuccess()],
                 'user' : "user.getAccountName()",
                 'hostname' : "user.getLastHostAddress()",
                 'sessionID' : userSessionIDforLogging,
                 }
            self.pyLogger.log(level, clean, extra=extra) 
                        
        def isDebugEnabled(self):
            return self.pyLogger.isEnabledFor(Logger.DEBUG)
        
        def isErrorEnabled(self):
            return self.pyLogger.isEnabledFor(Logger.ERROR)
        
        def isFatalEnabled(self):
            return self.pyLogger.isEnabledFor(Logger.FATAL)
        
        def isInfoEnabled(self):
            return self.pyLogger.isEnabledFor(Logger.INFO)
        
        def isTraceEnabled(self):
            return self.pyLogger.isEnabledFor(Logger.TRACE)
        
        def isWarningEnabled(self):
            return self.pyLogger.isEnabledFor(Logger.WARNING)
