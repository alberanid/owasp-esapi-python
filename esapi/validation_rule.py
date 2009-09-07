#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: The ValidationRule class is the parent class for the validators.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

from esapi.exceptions import ValidationException

class ValidationRule:
    def set_allow_none(self, flag):
        raise NotImplementedError()
        
    def get_type_name(self):
        raise NotImplementedError()
        
    def set_type_name(self, type_name):
        raise NotImplementedError()
    
    def assert_valid(self, context, input_):
        raise NotImplementedError()
        
    def get_valid(self, context, input_, error_list=None):
        raise NotImplementedError()
        
    def is_valid(self, context, input_):
        raise NotImplementedError()
        
    def whitelist(self, input_, whitelist):
        raise NotImplementedError()