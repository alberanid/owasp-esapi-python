#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: ESAPI locator class is provided to make it easy to gain access to the
    current ESAPI classes in use.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

# Todo

# IMPORTS AT THE BOTTOM TO PREVENT CIRCULAR IMPORTS

def from_fqn_get_instance(fqn):
    """
    Given a fully-qualified name of a python class in dotted notation, this
    function returns an instance of the referenced class.
    """
    try:
        dot = fqn.rindex('.')
    except ValueError, extra:
        raise ConfigurationException( _('There is an error in the application configuration'), 
            _("Fully-qualified name is malformed: %(name)s") % 
            {'name' : fqn},
            extra )
        
    modulename = fqn[:dot]
    classname = fqn[dot+1:]
    
    __import__(modulename)
    module = sys.modules[modulename]
    return getattr(module, classname)()
    

#theoretical new locator class
#class ESAPI(object):
#    """
#    ESAPI locator class is provided to make it easy to gain access to the current 
#    ESAPI classes in use. Use the set methods to override the reference 
#    implementations with instances of any custom ESAPI implementations.
#    """
#    @classmethod
#    def __getattr__(cls, interface_name):
#        prop = "ESAPI_%s" % interface_name
#        fqn = getattr(settings, prop)
#        instance = from_fqn_get_instance(fqn)
#        self.__setattr__(interface_name, instance)
#        
#    @classmethod
#    def load_security_configuration(cls):
#        if cls.security_configuration:
#            return
#            
#        fqn = 'settings.ESAPI_Security_Configuration'
#        self.security_configuration = from_fqn_get_instance(fqn)
#        
#    @classmethod
#    def logger(cls, key):
#        """
#        @param key: The class or module to associate the logger with.
#        @return: The current Logger associated with the specified class.
#        """
#        return cls.log_factory.get_logger(key)
#
#    @classmethod
#    def log(cls):
#        """
#        @return: The default logger
#        """
#        if cls.default_logger is None:
#            cls._default_logger = cls._log_factory().get_logger("DefaultLogger")
#        return cls._default_logger

        
class ESAPI():
    _authenticator = None
    _encoder = None
    _log_factory = None
    _access_controller = None
    _intrusion_detector = None
    _randomizer = None
    _encryptor = None
    _executor = None
    _validator = None
    _http_utilities = None
    _default_logger = None
    _security_configuration = None
    _message_util = None

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
    #        accessControllerName = cls.security_configuration().getAccessControlImplementation()
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
    #    if cls._authenticator is None:
    #        authenticatorName = cls.security_configuration().getAuthenticationImplementation()
    #        try:
    #            theClass = Class.forName(authenticatorName)
    #            cls._authenticator = theClass.newInstance()
    #        except (IllegalAccessException, ), ex:
    #            print ex + " Authenticator class (" + authenticatorName + " must be in class path."
    #            print ex + " Authenticator class (" + authenticatorName + " must be concrete."
    #            print ex + " Authenticator class (" + authenticatorName + " must have a no-arg constructor."
    #    return cls._authenticator
    #
    #    
    #def setAuthenticator(cls, authenticator):
    #    ESAPI.cls._authenticator = cls._authenticator
    #
    #

    @classmethod
    def encoder(cls):
        if cls._encoder is None:
            fqn = cls.security_configuration().get_encoder_implementation()
            cls._encoder = from_fqn_get_instance(fqn)
            
        return cls._encoder

    @classmethod
    def set_encoder(cls, new_encoder):
        cls._encoder = new_encoder

    @classmethod
    def encryptor(cls):
        if cls._encryptor is None:
            fqn = cls.security_configuration().get_encryption_implementation()
            cls._encryptor = from_fqn_get_instance(fqn)
            
        return cls._encryptor

    @classmethod
    def set_encryptor(cls, new_encryptor):
        cls._encryptor = new_encryptor

    #    
    #def executor(cls):
    #    if cls._executor is None:
    #        executorName = cls.security_configuration().getExecutorImplementation()
    #        try:
    #            theClass = Class.forName(executorName)
    #            cls._executor = theClass.newInstance()
    #        except (IllegalAccessException, ), ex:
    #            print ex + " Executor class (" + executorName + " must be in class path."
    #            print ex + " Executor class (" + executorName + " must be concrete."
    #            print ex + " Executor class (" + executorName + " must have a no-arg constructor."
    #    return cls._executor
    #
    #    
    #def setExecutor(cls, executor):
    #    ESAPI.cls._executor = cls._executor
    #
    #
    #def httpUtilities(self):
    #    if self.httpUtilities is None:
    #        httpUtilitiesName = self.get_security_configuration().getHTTPUtilitiesImplementation()
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
    #        intrusionDetectorName = cls.security_configuration().getIntrusionDetectionImplementation()
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
    @classmethod
    def log_factory(cls):
        """
        Get the current LogFactory being used by ESAPI. If there isn't one yet,
        it will create one, and then return this same LogFactory from then on.
        
        @return: The current LogFactory being used by ESAPI.
        """
        if cls._log_factory is None:
            fqn = cls.security_configuration().get_log_implementation()
            cls._log_factory = from_fqn_get_instance(fqn)
            cls._log_factory.set_application_name(cls.security_configuration().get_application_name())
            
        return cls._log_factory
          
    @classmethod
    def logger(cls, key):
        """
        @param key: The class or module to associate the logger with.
        @return: The current Logger associated with the specified class.
        """
        return cls.log_factory().get_logger(key)

    @classmethod
    def log(cls):
        """
        @return: The default logger
        """
        if cls._default_logger is None:
            cls._default_logger = cls._log_factory().get_logger("DefaultLogger")
        return cls._default_logger

    @classmethod
    def set_log_factory(cls, factory):
        """
        Change the current ESAPI LogFactory to the LogFactory provided. 
        @param factory: the LogFactory to set to be the current ESAPI LogFactory. 
        """
        cls._log_factory = factory
        
    @classmethod
    def randomizer(cls):
        if cls._randomizer is None:
            fqn = cls.security_configuration().get_randomizer_implementation()
            cls._randomizer = from_fqn_get_instance(fqn)
            
        return cls._randomizer

    @classmethod
    def set_randomizer(cls, new_randomizer):
        cls._randomizer = new_randomizer

    @classmethod
    def security_configuration(cls):       
        if cls._security_configuration is None:
            cls._security_configuration = DefaultSecurityConfiguration()
        return cls._security_configuration
       
    @classmethod
    def set_security_configuration(cls, new_security_config):
        cls._security_configuration = new_security_config

    @classmethod
    def validator(cls):
        if cls._validator is None:
            fqn = cls.security_configuration().get_validation_implementation()
            cls._validator = from_fqn_get_instance(fqn)
            
        return cls._validator

    @classmethod
    def set_validator(cls, new_validator):
        cls._validator = new_validator
     
    #
    #    
    #def messageUtil(cls):
    #    if ESAPI.cls.messageUtil is None:
    #        ESAPI.cls.messageUtil = DefaultMessageUtil()
    #    return ESAPI.cls.messageUtil

    
import sys

import esapi.conf.settings as settings
from esapi.reference.python_log_factory import PythonLogFactory
from esapi.reference.default_security_configuration import DefaultSecurityConfiguration
from esapi.translation import _

from esapi.exceptions import ConfigurationException