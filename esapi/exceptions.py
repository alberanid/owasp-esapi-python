#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: All the exceptions used by ESAPI.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

# Todo

from esapi.core import ESAPI
from esapi.logger import Logger
from esapi.translation import _

#####################
# EnterpriseSecurityException
#####################
class EnterpriseSecurityException(Exception):
    """
    EnterpriseSecurityException is the base class for all security related exceptions. You should pass in the root cause
    exception where possible. Constructors for classes extending EnterpriseSecurityException should be sure to call the
    appropriate super() method in order to ensure that logging and intrusion detection occur properly.
    
    All EnterpriseSecurityExceptions have two messages, one for the user and one for the log file. This way, a message
    can be shown to the user that doesn't contain sensitive information or unnecessary implementation details. Meanwhile,
    all the critical information can be included in the exception so that it gets logged.
    
    Note that the "logMessage" for ALL EnterpriseSecurityExceptions is logged in the log file. This feature should be
    used extensively throughout ESAPI implementations and the result is a fairly complete set of security log records.
    ALL EnterpriseSecurityExceptions are also sent to the IntrusionDetector for use in detecting anomolous patterns of
    application usage.
    """
    
    def __init__(self, user_message, log_message, cause=None):
        """
        Creates a new instance of EnterpriseSecurityException. This exception is automatically logged, so that simply by
        using this API, applications will generate an extensive security log. In addition, this exception is
        automatically registered with the IntrusionDetector, so that quotas can be checked.
        
        @param user_message: the message displayed to the user
        @param log_message: the message logged
        @param cause: the Exception that caused this one
        """
        Exception.__init__(self, user_message)
        
        self.user_message = user_message
        self.log_message = log_message
        self.cause = cause
        
        self.logger = ESAPI.logger("EnterpriseSecurityException")
        
        # Logging is done in add_exception()
        ESAPI.intrusion_detector().add_exception(self)
        
    def get_user_message(self):
        """
        Returns the message that is safe to display to users.
        
        @return: a string containing the message that is safe to display to
        users
        """
        return self.user_message
        
    def get_log_message(self):
        """
        Returns a message that is safe to display in logs, but probably not to
        users
        
        @return: a string containing a message that is safe to display in logs
        """
        cause = self.get_cause()
        causestr = None
        if cause:
            if hasattr(cause, 'get_log_message'):
                causestr = cause.get_log_message()
            elif hasattr(cause, '__str__'):
                causestr = str(cause)
            
        if causestr:
            return self.log_message + "\nCause: " + causestr
        else:
            return self.log_message
        
    def get_cause(self):
        """
        Returns the cause associated with this Exception
        
        @return: the Exception cause associated with this Exception
        """
        return self.cause
        
#####################
# AccessControlException
#####################  
class AccessControlException(EnterpriseSecurityException):
    """
    An AccessControlException should be raised when a user attempts to access a
    resource that they are not authorized for.
    """
    def __init__(self, user_message, log_message, cause=None):
        EnterpriseSecurityException.__init__(self, user_message, log_message, cause)

#####################
# AuthenticationExceptions
#####################
class AuthenticationException(EnterpriseSecurityException):
    """
    An AuthenticationException should be raised when anything goes wrong during
    login or logout. They are also appropriate for any problems related to
    identity management.
    """
    def __init__(self, user_message, log_message, cause=None):
        EnterpriseSecurityException.__init__(self, user_message, log_message, cause)
    
class AuthenticationAccountsException(AuthenticationException):
    def __init__(self, user_message, log_message, cause=None):
        AuthenticationException.__init__(self, user_message, log_message, cause)
    
class AuthenticationCredentialsException(AuthenticationException):
    def __init__(self, user_message, log_message, cause=None):
        AuthenticationException.__init__(self, user_message, log_message, cause)

class AuthenticationHostException(AuthenticationException):
    def __init__(self, user_message, log_message, cause=None):
        AuthenticationException.__init__(self, user_message, log_message, cause)
    
class AuthenticationLoginException(AuthenticationException):
    def __init__(self, user_message, log_message, cause=None):
        AuthenticationException.__init__(self, user_message, log_message, cause)
    
#####################
# AvailabilityException
#####################
class AvailabilityException(EnterpriseSecurityException):
    """
    An AvailabilityException should be raised when the availability of a limited
    resource is in jeopardy. For example, if a database connection pool runs out
    of connections, an availability exception should be raised.
    """
    def __init__(self, user_message, log_message, cause=None):
        EnterpriseSecurityException.__init__(self, user_message, log_message, cause)
    
#####################
# CertificateException
#####################
class CertificateException(EnterpriseSecurityException):
    """
    A CertificateException should be raised for any problems that arise during
    processing of digital certificates.
    """
    def __init__(self, user_message, log_message, cause=None):
        EnterpriseSecurityException.__init__(self, user_message, log_message, cause)
      
#####################
# ConfigurationException
#####################
      
class ConfigurationException(EnterpriseSecurityException):
    """
    A ConfigurationException should be raised for any problems related to 
    importing or parsing esapi.conf.settings.
    """
    def __init__(self, user_message, log_message, cause=None):
        EnterpriseSecurityException.__init__(self, user_message, log_message, cause)
    
#####################
# EncodingException
#####################
class EncodingException(EnterpriseSecurityException):
    """
    An ExecutorException should be raised for any problems that occur when
    encoding or decoding data.
    """
    def __init__(self, user_message, log_message, cause=None):
        EnterpriseSecurityException.__init__(self, user_message, log_message, cause)
    
#####################
# EncryptionException
#####################
class EncryptionException(EnterpriseSecurityException):
    """
    An EncryptionException should be raised for any problems related to
    encryption, hashing, or digital signatures.
    """
    def __init__(self, user_message, log_message, cause=None):
        EnterpriseSecurityException.__init__(self, user_message, log_message, cause)
    
#####################
# ExecutorException
#####################
class ExecutorException(EnterpriseSecurityException):
    """
    An ExecutorException should be raised for any problems that arise during the
    execution of a system executable.
    """
    def __init__(self, user_message, log_message, cause=None):
        EnterpriseSecurityException.__init__(self, user_message, log_message, cause)
    
#####################
# IntegrityException
#####################
class IntegrityException(EnterpriseSecurityException):
    """
    An IntegrityException should be raised when an integrity problem is 
    detected in a piece of data.
    """
    def __init__(self, user_message, log_message, cause=None):
        EnterpriseSecurityException.__init__(self, user_message, log_message, cause)

#####################
# IntrusionException
#####################
class IntrusionException(Exception):
    """
    An IntrusionException should be raised anytime an error condition arises 
    that is likely to be the result of an attack in progress. 
    IntrusionExceptions are handled specially by the IntrusionDetector, which 
    is equipped to respond by either specially logging the event, logging out 
    the current user, or invalidating the current user's account.
    """
    
    def __init__(self, user_message, log_message, cause=None):
        """
        Creates a new instance of IntrusionException.
        
        @param user_message: the message displayed to the user
        @param log_message: the message logged
        @param cause: the Exception that caused this one
        """
        Exception.__init__(self, user_message)
        
        self.user_message = user_message
        self.log_message = log_message
        self.cause = cause
        
        self.logger = ESAPI.logger("IntrusionException")
        self.logger.error(Logger.SECURITY_FAILURE, _("INTRUSION") + " - " + self.log_message)
        
        ESAPI.intrusion_detector().add_exception(self)
        
    def get_user_message(self):
        """
        Returns the message that is safe to display to users.
        
        @return: a string containing the message that is safe to display to
        users
        """
        return self.user_message
        
    def get_log_message(self):
        """
        Returns a message that is safe to display in logs, but probably not to
        users
        
        @return: a string containing a message that is safe to display in logs
        """
        cause = self.get_cause()
        causestr = None
        if cause:
            if hasattr(cause, 'get_log_message'):
                causestr = cause.get_log_message()
            elif hasattr(cause, '__str__'):
                causestr = str(cause)
            
        if causestr:
            return self.log_message + "\nCause: " + causestr
        else:
            return self.log_message
        
    def get_cause(self):
        """
        Returns the cause associated with this Exception
        
        @return: the Exception cause associated with this Exception
        """
        return self.cause
        
#####################
# ValidationExceptions
#####################
class ValidationException(EnterpriseSecurityException):
    """
    A ValidationException should be raised to indicate that the data provided 
    by the user or from some other external source does not match the 
    validation rules that have been specified for that data.
    """
    def __init__(self, user_message, log_message, cause=None, context=None):
        """
        Creates a new instance of ValidationException.
        
        @param user_message: the message displayed to the user
        @param log_message: the message logged
        @param cause: the Exception that caused this one
        @param context: the source that caused this Exception
        """
        
        EnterpriseSecurityException.__init__(self, user_message, log_message, cause)
        
        # The UI reference that caused this ValidationException
        self.context = None
        self.set_context(context)
        
    def get_context(self):
        """
        Returns the UI reference that caused this Exception
        
        @return: the context (source) that caused this Exception, as a string
        """
        return self.context
    
    def set_context(self, context):
        """
        Sets the UI reference that caused this ValidationException
        
        @param context: the context to set, as a string
        """
        # The UI reference that caused this ValidationException
        self.context = context
        
class ValidationAvailabilityException(ValidationException):
    """

    """
    def __init__(self, user_message, log_message, cause=None, context=None):
        ValidationException.__init__(self, user_message, log_message, cause, context)

class ValidationUploadException(ValidationException):
    """

    """
    def __init__(self, user_message, log_message, cause=None, context=None):
        ValidationException.__init__(self, user_message, log_message, cause, context)
        
