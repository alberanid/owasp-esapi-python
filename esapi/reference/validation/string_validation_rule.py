#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: A ValidationRule for strings.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

import re

from esapi.translation import _
from esapi.reference.validation.base_validation_rule import BaseValidationRule

from esapi.exceptions import ValidationException
from esapi.exceptions import EncodingException

from esapi.conf.constants import MAX_INTEGER, MIN_INTEGER

class StringValidationRule(BaseValidationRule):
    """
    This validator performs syntax validation of strings.
    """
    def __init__(self, type_name, encoder=None, whitelist_pattern=None):
        self.whitelist_patterns = []
        self.blacklist_patterns = []
        self.min_length = 0
        self.max_length = MAX_INTEGER
        
        BaseValidationRule.__init__(self, type_name, encoder)
        
        if whitelist_pattern:
            self.add_whitelist_pattern(whitelist_pattern)
            
    def add_whitelist_pattern(self, pattern_string):
        try:
            pattern = re.compile( pattern_string )
            self.whitelist_patterns.append(pattern)
        except Exception, extra:
            raise RuntimeError( 
                _("Validation misconfiguration, problem with specified pattern: %(pattern)s") %             
               {'pattern' : pattern_string}, 
               extra )
            
    def add_blacklist_pattern(self, pattern_string):
        try:
            pattern = re.compile( pattern_string )
            self.blacklist_patterns.append(pattern)
        except Exception, extra:
            raise RuntimeError( 
                _("Validation misconfiguration, problem with specified pattern: %(pattern)s") %             
               {'pattern' : pattern_string},
               extra )
            
    def set_minimum_length(self, length):
        self.min_length = length
        
    def set_maximum_length(self, length):
        self.max_length = length
        
    def get_valid(self, context, input_, error_list=None):
        try:
            # check none
            if input_ is None or len(input_) == 0:
                if self.allow_none:
                    return None
                raise ValidationException( 
                    _("%(context)s: Input required") % 
                   {'context' : context}, 
                   _("Input required: context=%(context)s, input=%(input)s") % 
                   {'context' : context,
                    'input' : input_}, 
                   context )
                        
            # canonicalize
            try:
                canonical = self.encoder.canonicalize( input_ )
            except EncodingException, extra:
                raise ValidationException( 
                    _("%(context)s: Invalid input. Encoding problem detected.") % 
                   {'context' : context}, 
                   _("Error canonicalizing user input"), 
                   extra, 
                   context )
                
            # check length
            if len(canonical) < self.min_length:           
                raise ValidationException(
                    _("%(context)s: Invalid input. The minimum length of %(min_length)s characters was not met.") %
                    { 'context' : context,
                      'min_length' : self.min_length, },
                    _("Input failed to meet minimum length of %(min_length)s by %(diff)s characters: context=%(context)s, type=%(type)s, input=%(input)s") %
                    { 'min_length' : self.min_length,
                      'diff' : self.min_length - len(canonical),
                      'context' : context,
                      'type' : self.get_type_name(),
                      'input' : input_,},
                    context )
                
            if len(canonical) > self.max_length:
                raise ValidationException(
                    _("%(context)s: Invalid input. The maximum length of %(max_length)s characters was exceeded.") %
                    { 'context' : context,
                      'max_length' : self.max_length, },
                    _("Input exceeds maximum allowed length of %(max_length)s by %(diff)s characters: context=%(context)s, type=%(type)s, input=%(input)s") %
                    { 'max_length' : self.max_length,
                      'diff' : len(canonical) - self.max_length,
                      'context' : context,
                      'type' : self.get_type_name(),
                      'input' : input_,},
                    context )
                
            # check whitelist patterns
            for pattern in self.whitelist_patterns:
                if not pattern.match(canonical):
                    raise ValidationException(
                        _("%(context)s: Invalid input. Please conform to regex %(regex)s%(optional)s") %
                        { 'context' : context,
                          'regex' : pattern.pattern,
                          'optional' : ('', ' with a maximum length of ' + str(self.max_length))[self.max_length == MAX_INTEGER],},
                        _("Invalid input: context=%(context)s, type(%(type)s)=%(pattern)s, input=%(input)s") %
                        { 'context' : context,
                          'type' : self.get_type_name(),
                          'pattern' : pattern.pattern,
                          'input' : input_},
                        context )
                          
            # check blacklist patterns
            for pattern in self.blacklist_patterns:
                if pattern.match(canonical):
                    raise ValidationException(
                        _("%(context)s: Invalid input. Dangerous input matching %(pattern)s detected.") %
                        { 'context' : context,
                          'pattern' : pattern.pattern,},
                        _("Dangerous input: context=%(context)s, type(%(type)s)=%(pattern)s, input=%(input)s") %
                        { 'context' : context,
                          'type' : self.get_type_name(),
                          'pattern' : pattern.pattern,
                          'input' : input_,},
                        context )
                          
            # validation passed
            return canonical
    
        except ValidationException, extra:
            if error_list is not None:
                error_list[context] = extra
            else:
                raise
        
