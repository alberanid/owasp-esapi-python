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
        
    def get_safe(self, context, input_):
        """
        Return a best-effort safe value even in the case of input errors.
        """
        raise NotImplementedError()
        
    def is_valid(self, context, input_):
        raise NotImplementedError()
        
    def whitelist(self, input_, whitelist):
        raise NotImplementedError()