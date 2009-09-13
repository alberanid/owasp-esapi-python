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
        
class ESAPI(): 
    _log_factory = None
    _security_configuration = None
    
    def gen_get_method(interface):
        # store instances in cls._interface
        # eg. cls._encoder
        priv_attr = '_' + interface
        
        @classmethod
        def func(cls):
            if cls.__dict__.get(priv_attr) is None:
                klass = cls.security_configuration().get_class_for_interface(interface)
                cls.__dict__[priv_attr] = klass()
            return cls.__dict__.get(priv_attr)
            
        return func
        
    def gen_set_method(interface):
        priv_attr = '_' + interface
        
        @classmethod
        def func(cls, new_value):
            cls.__dict__[priv_attr] = new_value
            
    
    access_controller = gen_get_method('access_controller')
    set_access_controller = gen_get_method('access_controller')
            
    authenticator = gen_get_method('authenticator')
    set_authenticator = gen_set_method('authenticator')
       
    encoder = gen_get_method('encoder')
    set_encoder = gen_set_method('encoder')
    
    encryptor = gen_get_method('encryptor')
    set_encryptor = gen_set_method('encryptor')
    
    randomizer = gen_get_method('randomizer')
    set_randomizer = gen_set_method('randomizer')
    
    user = gen_get_method('user')
    set_user = gen_set_method('user')
    
    validator = gen_get_method('validator')
    set_validator = gen_set_method('validator')
    
    http_utilities = gen_get_method('http_utilities')
    set_http_utilities = gen_set_method('http_utilities')
    
    intrusion_detector = gen_get_method('intrusion_detector')
    set_intrusion_detector = gen_set_method('intrusion_detector')
    
    executor = gen_get_method('executor')
    set_executor = gen_set_method('executor')

    @classmethod
    def log_factory(cls):
        """
        Get the current LogFactory being used by ESAPI. If there isn't one yet,
        it will create one, and then return this same LogFactory from then on.
        
        @return: The current LogFactory being used by ESAPI.
        """
        if cls._log_factory is None:
            klass = cls.security_configuration().get_class_for_interface('log_factory')
            cls._log_factory = klass()
            cls._log_factory.set_application_name(cls.security_configuration().get_application_name())
            
        return cls._log_factory
        
    @classmethod
    def set_log_factory(cls, factory):
        """
        Change the current ESAPI LogFactory to the LogFactory provided. 
        @param factory: the LogFactory to set to be the current ESAPI LogFactory. 
        """
        cls._log_factory = factory
          
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
    def security_configuration(cls):       
        if cls._security_configuration is None:
            cls._security_configuration = DefaultSecurityConfiguration()
        return cls._security_configuration
       
    set_security_configuration = gen_set_method('security_configuration')
    
    @classmethod
    def current_request(cls):
        return cls.http_utilities().current_request
    
    @classmethod
    def current_response(cls):
        return cls.http_utilities().current_response

    
import sys

import esapi.conf.settings as settings
from esapi.reference.python_log_factory import PythonLogFactory
from esapi.reference.default_security_configuration import DefaultSecurityConfiguration
from esapi.translation import _

from esapi.exceptions import ConfigurationException
