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

# Todo

import sys

from esapi.reference.python_log_factory import PythonLogFactory
from esapi.reference.default_security_configuration import DefaultSecurityConfiguration
from esapi.translation import _

"""
ESAPI locator class is provided to make it easy to gain access to the current ESAPI classes in use.
Use the set methods to override the reference implementations with instances of any custom ESAPI implementations.
"""

authenticator = None
encoder = None
logFactory = None
accessController = None
intrusionDetector = None
randomizer = None
encryptor = None
executor = None
validator = None
httpUtilities = None
defaultLogger = None
securityConfiguration = None
messageUtil = None

#def currentRequest():
#    """
#    Get the current HTTP Servlet Request being processed.
#    @return the current HTTP Servlet Request.
#    """
#    return self.httpUtilities().getCurrentRequest()
#
#def currentResponse():
#    """
#    Get the current HTTP Servlet Response being generated.
#    @return the current HTTP Servlet Response.
#    """
#    return self.httpUtilities().getCurrentResponse()
#   
#def accessController():
#    """
#    @return the current ESAPI AccessController object being used to maintain the access control rules for this application.
#    """
#    if self.accessController is None:
#        accessControllerName = cls.getSecurityConfiguration().getAccessControlImplementation()
#        try:
#            theClass = Class.forName(accessControllerName)
#            cls.accessController = theClass.newInstance()
#        except (IllegalAccessException, ), ex:
#            print ex + " AccessController class (" + accessControllerName + " must be in class path."
#            print ex + " AccessController class (" + accessControllerName + " must be concrete."
#            print ex + " AccessController class (" + accessControllerName + " must have a no-arg constructor."
#    return cls.accessController
#
#    
#def setAccessController(cls, controller):
#    ESAPI.cls.accessController = controller
#
#    
#def authenticator(cls):
#    if cls.authenticator is None:
#        authenticatorName = cls.getSecurityConfiguration().getAuthenticationImplementation()
#        try:
#            theClass = Class.forName(authenticatorName)
#            cls.authenticator = theClass.newInstance()
#        except (IllegalAccessException, ), ex:
#            print ex + " Authenticator class (" + authenticatorName + " must be in class path."
#            print ex + " Authenticator class (" + authenticatorName + " must be concrete."
#            print ex + " Authenticator class (" + authenticatorName + " must have a no-arg constructor."
#    return cls.authenticator
#
#    
#def setAuthenticator(cls, authenticator):
#    ESAPI.cls.authenticator = cls.authenticator
#
#    
#def encoder(cls):
#    if cls.encoder is None:
#        encoderName = cls.getSecurityConfiguration().getEncoderImplementation()
#        try:
#            theClass = Class.forName(encoderName)
#            cls.encoder = theClass.newInstance()
#        except (IllegalAccessException, ), ex:
#            print ex + " Encoder class (" + encoderName + " must be in class path."
#            print ex + " Encoder class (" + encoderName + " must be concrete."
#            print ex + " Encoder class (" + encoderName + " must have a no-arg constructor."
#    return cls.encoder
#
#    
#def setEncoder(cls, encoder):
#    ESAPI.cls.encoder = cls.encoder
#
#    
#def encryptor(cls):
#    if cls.encryptor is None:
#        encryptorName = cls.getSecurityConfiguration().getEncryptionImplementation()
#        try:
#            theClass = Class.forName(encryptorName)
#            cls.encryptor = theClass.newInstance()
#        except (IllegalAccessException, ), ex:
#            print ex + " Encryptor class (" + encryptorName + " must be in class path."
#            print ex + " Encryptor class (" + encryptorName + " must be concrete."
#            print ex + " Encryptor class (" + encryptorName + " must have a no-arg constructor."
#    return cls.encryptor
#
#    
#def setEncryptor(cls, encryptor):
#    ESAPI.cls.encryptor = cls.encryptor
#

def getEncryptor():
    global encryptor

    if encryptor is None:
        fqn = getSecurityConfiguration().getEncryptionImplementation()
        moduleName = '.'.join(fqn.split('.')[:-1])
        __import__(moduleName)
        module = sys.modules[moduleName]
        className = fqn.split('.')[-1]
        encryptor = getattr(module, className)()
        
    return encryptor

def setencryptor(newEncryptor):
    global encryptor
    encryptor = newEncryptor

#    
#def executor(cls):
#    if cls.executor is None:
#        executorName = cls.getSecurityConfiguration().getExecutorImplementation()
#        try:
#            theClass = Class.forName(executorName)
#            cls.executor = theClass.newInstance()
#        except (IllegalAccessException, ), ex:
#            print ex + " Executor class (" + executorName + " must be in class path."
#            print ex + " Executor class (" + executorName + " must be concrete."
#            print ex + " Executor class (" + executorName + " must have a no-arg constructor."
#    return cls.executor
#
#    
#def setExecutor(cls, executor):
#    ESAPI.cls.executor = cls.executor
#
#
#def httpUtilities(self):
#    if self.httpUtilities is None:
#        httpUtilitiesName = self.getSecurityConfiguration().getHTTPUtilitiesImplementation()
#        try:
#            theClass = Class.forName(httpUtilitiesName)
#            cls.httpUtilities = theClass.newInstance()
#        except (IllegalAccessException, ), ex:
#            print ex + " HTTPUtilities class (" + httpUtilitiesName + ") must be in class path."
#            print ex + " HTTPUtilities class (" + httpUtilitiesName + ") must be concrete."
#            print ex + " HTTPUtilities class (" + httpUtilitiesName + ") must have a no-arg constructor."
#    return self.httpUtilities
#
#    
#def setHttpUtilities(self, httpUtilities):
#    self.httpUtilities = httpUtilities
#
#    
#def intrusionDetector(cls):
#    if cls.intrusionDetector is None:
#        intrusionDetectorName = cls.getSecurityConfiguration().getIntrusionDetectionImplementation()
#        try:
#            theClass = Class.forName(intrusionDetectorName)
#            cls.intrusionDetector = theClass.newInstance()
#        except (IllegalAccessException, ), ex:
#            print ex + " IntrusionDetector class (" + intrusionDetectorName + " must be in class path."
#            print ex + " IntrusionDetector class (" + intrusionDetectorName + " must be concrete."
#            print ex + " IntrusionDetector class (" + intrusionDetectorName + " must have a no-arg constructor."
#    return cls.intrusionDetector
#
#    
#def setIntrusionDetector(cls, intrusionDetector):
#    ESAPI.cls.intrusionDetector = cls.intrusionDetector
#
#    
def getLogFactory():
    """
    Get the current LogFactory being used by ESAPI. If there isn't one yet, it will create one, and then 
    return this same LogFactory from then on.
    @return The current LogFactory being used by ESAPI.
    """
    global logFactory

    if logFactory is None:
        fqn = getSecurityConfiguration().getLogImplementation()
        moduleName = '.'.join(fqn.split('.')[:-1])
        __import__(moduleName)
        module = sys.modules[moduleName]
        className = fqn.split('.')[-1]
        logFactory = getattr(module, className)()
        logFactory.setApplicationName(getSecurityConfiguration().getApplicationName())
        
    return logFactory
      
def getLogger(classOrMod):
    """
    @param classOrMod The class or module to associate the logger with.
    @return The current Logger associated with the specified class.
    """
    return getLogFactory().getLogger(classOrMod)

def log():
    """
    @return The default logger
    """
    global defaultLogger
    
    if defaultLogger is None:
        defaultLogger = logFactory().getLogger("DefaultLogger")
    return defaultLogger

def setLogFactory(factory):
    """
    Change the current ESAPI LogFactory to the LogFactory provided. 
    @param factory
           the LogFactory to set to be the current ESAPI LogFactory. 
    """
    global logFactory
    
    logFactory = factory

   
def getRandomizer():
    global randomizer

    if randomizer is None:
        fqn = getSecurityConfiguration().getRandomizerImplementation()
        moduleName = '.'.join(fqn.split('.')[:-1])
        __import__(moduleName)
        module = sys.modules[moduleName]
        className = fqn.split('.')[-1]
        randomizer = getattr(module, className)()
        
    return randomizer

def setRandomizer(newRandomizer):
    global randomizer
    randomizer = newRandomizer

def getSecurityConfiguration():
    global securityConfiguration
    
    if securityConfiguration is None:
        securityConfiguration = DefaultSecurityConfiguration()
    return securityConfiguration
   
def setSecurityConfiguration(newSecurityConfiguration):
    global securityConfiguration
    securityConfiguration = newSecurityConfiguration

#  
#def validator(cls):
#    if cls.validator is None:
#        validatorName = cls.getSecurityConfiguration().getValidationImplementation()
#        try:
#            theClass = Class.forName(validatorName)
#            cls.validator = theClass.newInstance()
#        except (IllegalAccessException, ), ex:
#            print ex + " Validator class (" + validatorName + ") must be in class path."
#            print ex + " Validator class (" + validatorName + ") must be concrete."
#            print ex + " Validator class (" + validatorName + ") must have a no-arg constructor."
#    return cls.validator
#
#    
#def setValidator(cls, validator):
#    ESAPI.cls.validator = cls.validator
#
#    
#def messageUtil(cls):
#    if ESAPI.cls.messageUtil is None:
#        ESAPI.cls.messageUtil = DefaultMessageUtil()
#    return ESAPI.cls.messageUtil
