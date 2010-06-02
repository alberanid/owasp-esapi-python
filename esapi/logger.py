#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: The Logger interface defines a set of methods that can be used to log
    security events.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

# Todo

from esapi.translation import _

from esapi.conf.constants import MAX_INTEGER, MIN_INTEGER

class Logger:
    """
    The Logger interface defines a set of methods that can be used to log
    security events. It supports a hierarchy of logging levels which can be 
    configured at runtime to determine the severity of events that are logged, and
    those below the current threshold that are discarded. Implementors should use 
    a well established logging library as it is quite difficult to create a 
    high-performance logger.
   
    The logging levels defined by this interface (in descending order) are:

        - fatal (highest value)
        - error
        - warning
        - info
        - debug
        - trace (lowest value)

    ESAPI also allows for the definition of the type of log event that is being 
    generated. The Logger interface predefines 4 types of Log events: 
    SECURITY_SUCCESS, SECURITY_FAILURE, EVENT_SUCCESS, EVENT_FAILURE. 
    Your implementation can extend or change this list if desired. 

    This Logger allows callers to determine which logging levels are enabled, and 
    to submit events at different severity levels.
    Implementors of this interface should:

        - provide a mechanism for setting the logging level threshold that is 
        currently enabled. This usually works by logging all events at and above that 
        severity level, and discarding all events below that level. This is usually 
        done via configuration, but can also be made accessible programmatically.
        - ensure that dangerous HTML characters are encoded before they are logged 
        to defend against malicious injection into logs that might be viewed in an 
        HTML based log viewer.    
        - encode any CRLF characters included in log data in order to prevent 
        log injection attacks.    
        - avoid logging the user's session ID. Rather, they should log 
        something equivalent like a generated logging session ID, or a hashed 
        value of the session ID so they can track session specific events 
        without risking the exposure of a live session's ID.
        - record the following information with each event:
            - identity of the user that caused the event,
            - a description of the event (supplied by the caller),
            - whether the event succeeded or failed (indicated by the caller),
            - severity level of the event (indicated by the caller),
            - that this is a security relevant event (indicated by the caller),
            - hostname or IP where the event occurred (and ideally the user's source IP
            as well),
            - a time stamp
     
    Custom logger implementations might also:
        - filter out any sensitive data specific to the current application or 
    organization, such as credit cards, social security numbers, etc.

    In the default implementation, this interface is implemented by PythonLogger, 
    which is an inner class in PythonLogFactory.java. PythonLogger uses the logging 
    package as the basis for its logging implementation. This default 
    implementation implements requirements #1 thru #5 above.
    Customization: It is expected that most organizations will implement their own 
    custom Logger class in order to integrate ESAPI logging with their logging 
    infrastructure. The ESAPI Reference Implementation is intended to provide a 
    simple functional example of an implementation.
    """
    
    class EventType:
        """
        Defines the type of log event that is being generated. The Logger 
        interface defines 4 types of Log events: 
        SECURITY_SUCCESS, SECURITY_FAILURE, EVENT_SUCCESS, EVENT_FAILURE. 
        Your implementation can extend or change this list if desired. 
        """
        
        def __init__(self, name, success):
            self.type = name
            self.success = success
            
        def is_success(self):
            return self.success
        
        def __str__(self):
            return self.type
        
        def __repr__(self):
            return 'EventType("%s", %s)' % (self.type, self.success)
        
    # A security type of log event that has succeeded. This is one of 4 
    # predefined ESAPI logging events. New events can be added.
    SECURITY_SUCCESS = EventType(_("SECURITY SUCCESS"), True)
    
    # A security type of log event that has failed. This is one of 4 predefined
    # ESAPI logging events. New events can be added.
    SECURITY_FAILURE = EventType(_("SECURITY FAILURE"), False)
    
    # A non-security type of log event that has succeeded. This is one of 4 
    # predefined ESAPI logging events. New events can be added.
    EVENT_SUCCESS = EventType(_("EVENT SUCCESS"), True)
    
    # A non-security type of log event that has failed. This is one of 4 
    # predefined ESAPI logging events. New events can be added.
    EVENT_FAILURE = EventType(_("EVENT FAILURE"), False)
    
    # The Logger interface defines 6 logging levels: 
    # FATAL, ERROR, WARNING, INFO, DEBUG, TRACE.
    # It also supports ALL, which logs all events, and OFF, which disables all 
    # logging. Your implementation can extend or change this list if desired.
    
    # OFF indicates that no messages should be logged. This level is 
    # initialized to Java's Integer.MAX_VALUE.
    OFF = MAX_INTEGER -1
    
    # FATAL indicates that only FATAL messages should be logged. This level is 
    # initialized to 1000.
    FATAL = 1000
    
    # ERROR indicates that ERROR messages and above should be logged. 
    # This level is initialized to 800.
    ERROR = 800
    
    # WARNING indicates that WARNING messages and above should be logged. 
    # This level is initialized to 600.
    WARNING = 600
    
    # INFO indicates that INFO messages and above should be logged. 
    # This level is initialized to 400.
    INFO = 400
    
    # DEBUG indicates that DEBUG messages and above should be logged. 
    # This level is initialized to 200.
    DEBUG = 200
    
    # TRACE indicates that TRACE messages and above should be logged. 
    # This level is initialized to 100.
    TRACE = 100
    
    # ALL indicates that all messages should be logged. This level is 
    # initialized to Java's Integer.MIN_VALUE.
    ALL = MIN_INTEGER
    
    def __init__(self):
        pass
        
    def set_level(self, level):
        """
        Dynamically set the logging severity level. All events of this level 
        and higher will be logged from this point forward for all logs. All 
        events below this level will be discarded.
        
        @param level: The level to set the logging level to.
        """
        raise NotImplementedError()
        
    def fatal(self, event_type, message, exception=None):
        """
        Log a fatal level security event if 'fatal' level logging is enabled 
        and also record the stack trace associated with the event.
     
        @param event_type: the type of event
        @param message: the message to log
        @param exception: the exception to be logged
        """
        raise NotImplementedError()
        
    def is_fatal_enabled(self):
        """
        Allows the caller to determine if messages logged at this level
        will be discarded, to avoid performing expensive processing.
        
        @return: True if fatal level messages will be output to the log
        """
        raise NotImplementedError()
        
    def error(self, event_type, message, exception=None):
        """
        Log an error level security event if 'error' level logging is enabled 
        and also record the stack trace associated with the event.
        
        @param event_type: the type of event
        @param message: the message to log
        @param exception: the exception to be logged
        """
        raise NotImplementedError()
    
    def is_error_enabled(self):
        """
        Allows the caller to determine if messages logged at this level
        will be discarded, to avoid performing expensive processing.
        
        @return: True if error level messages will be output to the log
        """
        raise NotImplementedError()
    
    def warning(self, event_type, message, exception=None):
        """
        Log a warning level security event if 'warning' level logging is 
        enabled and also record the stack trace associated with the event.
     
        @param event_type: the type of event
        @param message: the message to log
        @param exception: the exception to be logged
        """
        raise NotImplementedError()
    
    def is_warning_enabled(self):
        """
        Allows the caller to determine if messages logged at this level
        will be discarded, to avoid performing expensive processing.
     
         @return: True if warning level messages will be output to the log
        """
        raise NotImplementedError()
    
    def info(self, event_type, message, exception=None):
        """
        Log an info level security event if 'info' level logging is enabled 
        and also record the stack trace associated with the event.
     
        @param event_type: the type of event
        @param message: the message to log
        @param exception: the exception to be logged
        """
        raise NotImplementedError()
        
    def is_info_enabled(self):
        """
        Allows the caller to determine if messages logged at this level
        will be discarded, to avoid performing expensive processing.
        
        @return: True if info level messages will be output to the log
        """
        raise NotImplementedError()
        
    def debug(self, event_type, message, exception=None):
        """
        Log a debug level security event if 'debug' level logging is enabled 
        and also record the stack trace associated with the event.
        
        @param event_type: the type of event
        @param message: the message to log
        @param exception: the exception to be logged 
        """
        raise NotImplementedError()
    
    def is_debug_enabled(self):
        """
        Allows the caller to determine if messages logged at this level
        will be discarded, to avoid performing expensive processing.
        
        @return: True if debug level messages will be output to the log
        """
        raise NotImplementedError()
        
    def trace(self, event_type, message, exception=None):
        """
        Log a trace level security event if 'trace' level logging is enabled 
        and also record the stack trace associated with the event.
     
        @param event_type: the type of event
        @param message: the message to log
        @param exception: the exception to be logged
        """
        raise NotImplementedError()
    
    def is_trace_enabled(self):
        """
        Allows the caller to determine if messages logged at this level
        will be discarded, to avoid performing expensive processing.
        
        @return: True if the trace level messages will be output to the log
        """
        raise NotImplementedError()