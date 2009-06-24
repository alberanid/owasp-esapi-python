#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
OWASP Enterprise Security API (ESAPI)
 
This file is part of the Open Web Application Security Project (OWASP)
Enterprise Security API (ESAPI) project. For details, please see
<a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
Copyright (c) 2009 - The OWASP Foundation

The ESAPI is published by OWASP under the BSD license. You should read and 
accept the LICENSE before you use, modify, and/or redistribute this software.

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
    Reference implementation of the LogFactory and Logger interfaces. This 
    implementation uses the Python logging package, and marks each log message 
    with the currently logged in user and the word "SECURITY" for security 
    related events. 
    
    @author Craig Younkins (craig.younkins@owasp.org)
    @see esapi.log_factory
    @see esapi.reference.python_log_factory.PythonLogFactory.PythonLogger
    """
    
    application_name = None
    loggers_map = {}
    
    def __init__(self, application_name=None):
        """
        Constructor for this implementation of the LogFactory interface.
        
        @param application_name The name of the application this logger is being constructed for.
        """
        LogFactory.__init__(self)
        self.application_name = application_name
        
    def set_application_name(self, application_name):
        self.application_name = application_name
        
    def get_logger(self, key):
        if not self.loggers_map.has_key(key):
            self.loggers_map[key] = self.PythonLogger(self.application_name, key)
            
        return self.loggers_map[key]
    
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
        application_name = None
        
        # The module name using this log.
        module_name = None
        
        def __init__(self, application_name, module_name):
            """
            Public constructor should only ever be called via the appropriate LogFactory
            
            @param application_name the application name
            @param module_name the module name
            """
            Logger.__init__(self)
            
            self.application_name = application_name
            self.module_name = module_name
            
            # Set the log levels. These are straight from logger.py
            logging.addLevelName(Logger.OFF, "OFF")
            logging.addLevelName(Logger.FATAL, "FATAL")
            logging.addLevelName(Logger.ERROR, "ERROR")
            logging.addLevelName(Logger.WARNING, "WARNING")
            logging.addLevelName(Logger.INFO, "INFO")
            logging.addLevelName(Logger.DEBUG, "DEBUG")
            logging.addLevelName(Logger.TRACE, "TRACE")
            logging.addLevelName(Logger.ALL, "ALL")
            
            # Make our logger
            self.pyLogger = logging.getLogger(application_name + "." + module_name)
            
            # create console handler and set level to debug
            console_handler = logging.StreamHandler()
            console_handler.setLevel(Logger.ALL)
            # create formatter
            formatter = logging.Formatter("%(levelname)s %(name)s - %(eventType)s - %(user)s@%(hostname)s:%(sessionID)s -- %(message)s")
            # add formatter to console_handler
            console_handler.setFormatter(formatter)
            # add console_handler to logger
            self.pyLogger.addHandler(console_handler)

        def set_level(self, level):
            """
            Note: In this implementation, this change is not persistent,
            meaning that if the application is restarted, the log level will revert to the level defined in the
            ESAPI SecurityConfiguration properties file.
            """
            self.pyLogger.setLevel(level)
            
        def trace(self, event_type, message, exception=None):
            self.log(Logger.TRACE, event_type, message, exception)
            
        def debug(self, event_type, message, exception=None):
            self.log(Logger.DEBUG, event_type, message, exception)
            
        def info(self, event_type, message, exception=None):
            self.log(Logger.INFO, event_type, message, exception)
            
        def warning(self, event_type, message, exception=None):
            self.log(Logger.WARNING, event_type, message, exception)
            
        def error(self, event_type, message, exception=None):
            self.log(Logger.ERROR, event_type, message, exception)
            
        def fatal(self, event_type, message, exception=None):
            self.log(Logger.FATAL, event_type, message, exception)
            
        def log(self, level, event_type, message, exception=None):
            """
            Log the message after optionally encoding any special characters 
            that might be dangerous when viewed by an HTML based log viewer. 
            Also encode any carriage returns and line feeds to prevent log
            injection attacks. This logs all the supplied parameters plus the 
            user ID, user's source IP, a logging specific session ID, and the 
            current date/time.
            
            It will only log the message if the current logging level is 
            enabled, otherwise it will discard the message.
            
            @param level the severity level of the security event
            @param event_type the event_type of the event (SECURITY, FUNCTIONALITY, etc.)
            @param message the message
            @param exception an exception
            """
            # Before we waste all kinds of time preparing this event for the 
            # log, let check to see if its loggable
            if not self.pyLogger.isEnabledFor(level): 
                return
            
            #user = ESAPI.authenticator().getCurrentUser()
            
            # create a random session number for the user to represent the 
            # user's 'session', if it doesn't exist already
            user_session_id_for_logging = _("unknown")
            
            # Add HTTP Session information here
            
            # ensure there's something to log
            if message is None:
                message = ""
                
            # ensure no CRLF injection into logs for forging records
            clean = message.replace('\n', '_').replace('\r', '_')
            if esapi.core.getSecurityConfiguration().get_log_encoding_required():
                clean = esapi.core.encoder().encode_for_html(message)
                if message != clean:
                    clean += " (Encoded)"
                      
            extra = {
                 'eventType' : str(event_type),
                 'eventSuccess' : [_("SUCCESS"),_("FAILURE")][event_type.isSuccess()],
                 'user' : "user.getAccountName()",
                 'hostname' : "user.getLastHostAddress()",
                 'sessionID' : user_session_id_for_logging,
                 }
            self.pyLogger.log(level, clean, extra=extra) 
                        
        def is_debug_enabled(self):
            return self.pyLogger.isEnabledFor(Logger.DEBUG)
        
        def is_error_enabled(self):
            return self.pyLogger.isEnabledFor(Logger.ERROR)
        
        def is_fatal_enabled(self):
            return self.pyLogger.isEnabledFor(Logger.FATAL)
        
        def is_info_enabled(self):
            return self.pyLogger.isEnabledFor(Logger.INFO)
        
        def is_trace_enabled(self):
            return self.pyLogger.isEnabledFor(Logger.TRACE)
        
        def is_warning_enabled(self):
            return self.pyLogger.isEnabledFor(Logger.WARNING)
