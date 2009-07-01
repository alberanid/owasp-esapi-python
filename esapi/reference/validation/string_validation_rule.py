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

import re

from esapi.reference.validation.base_validation_rule import BaseValidationRule
from esapi.reference.default_encoder import DefaultEncoder

from esapi.exceptions import ValidationException
from esapi.exceptions import EncodingException

class StringValidationRule(BaseValidationRule):
    """
    This validator performs syntax validation of strings.
    """
    def __init__(self, type_name, encoder=None, whitelist_pattern=None):
        self.whitelist_patterns = []
        self.blacklist_patterns = []
        self.min_length = 0
        self.max_length = 2**31
        
        BaseValidationRule.__init__(self, type_name, encoder)
        
        if whitelist_pattern:
            self.add_whitelist_pattern(whitelist_pattern)
            
    def add_whitelist_pattern(self, pattern_string):
        try:
            pattern = re.compile( pattern_string )
            self.whitelist_patterns.append(pattern)
        except Exception, extra:
            raise RuntimeError("Validation misconfiguration, problem with specified pattern: " + 
                  pattern_string, extra )
            
    def add_blacklist_pattern(self, pattern_string):
        try:
            pattern = re.compile( pattern_string )
            self.blacklist_patterns.append(pattern)
        except Exception, extra:
            raise RuntimeError("Validation misconfiguration, problem with specified pattern: " + 
            pattern_string, extra )
            
    def set_minimum_length(self, length):
        self.min_length = length
        
    def set_maximum_length(self, length):
        self.max_length = length
        
    def get_valid(self, context, input_, error_list=None):
        # check none
        if input_ is None or len(input_) == 0:
            if self.allow_none:
                return None
            raise ValidationException( context + ": Input required", 
                    "Input required: context=" + context + ", input=" + input_, context )
                    
        # canonicalize
        try:
            canonical = self.encoder.canonicalize( input_ )
        except EncodingException, extra:
            raise ValidationException(context + ": Invalid input. Encoding problem detected.", 
                  "Error canonicalizing user input", extra, context)
            
        # check length
        if len(canonical) < self.min_length:           
            raise ValidationException(
                "%(context)s: Invalid input. The minimum length of %(min_length)s characters was not met." %
                { 'context' : context,
                  'min_length' : self.min_length, },
                "Input failed to meet minimum length of %(min_length)s by %(diff)s characters: context=%(context)s, type=%(type)s, input=%(input)s" %
                { 'min_length' : self.min_length,
                  'diff' : self.min_length - len(canonical),
                  'context' : context,
                  'type' : self.get_type_name(),
                  'input' : input_,},
                context)
            
        if len(canonical) > self.max_length:
            raise ValidationException(
                "%(context)s: Invalid input. The maximum length of %(max_length)s characters was exceeded." %
                { 'context' : context,
                  'max_length' : self.max_length, },
                "Input exceeds maximum allowed length of %(max_length)s by %(diff)s characters: context=%(context)s, type=%(type)s, input=%(input)s" %
                { 'max_length' : self.max_length,
                  'diff' : len(canonical) - self.max_length,
                  'context' : context,
                  'type' : self.get_type_name(),
                  'input' : input_,},
                context)
            
        # check whitelist patterns
        for pattern in self.whitelist_patterns:
            if not pattern.match(canonical):
                raise ValidationException(
                    "%(context)s: Invalid input. Please conform to regex %(regex)s%(optional)s" %
                    { 'context' : context,
                      'regex' : pattern.pattern,
                      'optional' : ('', ' with a maximum length of ' + self.max_length)[self.max_length == 2**31],},
                    "Invalid input: context=%(context)s, type(%(type)s)=%(pattern)s, input=%(input)s" %
                    { 'context' : context,
                      'type' : self.get_type_name(),
                      'pattern' : pattern.pattern,
                      'input' : input_},
                    context)
                      
        # check blacklist patterns
        for pattern in self.blacklist_patterns:
            if pattern.match(canonical):
                raise ValidationException(
                    "%(context)s: Invalid input. Dangerous input matching %(pattern)s detected." %
                    { 'context' : context,
                      'pattern' : pattern.pattern,},
                    "Dangerous input: context=%(context)s, type(%(type)s)=%(pattern)s, input=%(input)s" %
                    { 'context' : context,
                      'type' : self.get_type_name(),
                      'pattern' : pattern.pattern,
                      'input' : input_,},
                    context)
                      
        # validation passed
        return canonical
        
    def sanitize(self, context, input_):
        return self.whitelist(input_, DefaultEncoder.CHAR_ALPHANUMERICS)