#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: A BaseValidationRule performs syntax and possibly semantic validation of a 
    single piece of data from an untrusted source.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

from esapi.validation_rule import ValidationRule
from esapi.core import ESAPI

from esapi.exceptions import ValidationException

class BaseValidationRule(ValidationRule):
    """
    A BaseValidationRule performs syntax and possibly semantic validation of a 
    single piece of data from an untrusted source.
    """
    def __init__(self, type_name, encoder=None):
        self.type_name = None
        self.allow_none = False
        self.encoder = None
    
        if encoder:
            self.set_encoder( encoder )
        else:
            self.set_encoder( ESAPI.encoder() )
        
        self.set_type_name(type_name)
        
    def get_valid(self, context, input_, error_list=None):
        raise NotImplementedError()
        
    def set_allow_none(self, flag):
        self.allow_none = flag
        
    def get_type_name(self):
        return self.type_name
        
    def set_type_name(self, type_name):
        self.type_name = type_name
        
    def set_encoder(self, encoder):
        self.encoder = encoder
        
    def assert_valid(self, context, input_):
        self.get_valid(context, input_)
        
    def get_safe(self, context, input_):
        try:
            return self.get_valid( context, input_ )
        except ValidationException, extra:
            return None
            
    def is_valid(self, context, input_):
        try:
            self.get_valid(context, input_)
            return True
        except ValidationException, extra:
            return False
        except Exception, extra:
            return False
