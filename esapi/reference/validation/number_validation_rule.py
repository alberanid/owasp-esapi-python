#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: A ValidationRule to validate numbers. 
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

from esapi.reference.validation.base_validation_rule import BaseValidationRule
from esapi.translation import _

from esapi.exceptions import ValidationException
from esapi.exceptions import EncodingException

class NumberValidationRule(BaseValidationRule):
    def __init__(self, type_name, num_type, encoder, min_value, max_value):
        BaseValidationRule.__init__(self, type_name, encoder)
        
        self.num_type = num_type
        self.min_value = min_value
        self.max_value = max_value
        
    def get_valid(self, context, input_, error_list=None):
        try:        
            # check for none
            if input_ is None or len(input_) == 0:
                if self.allow_none:
                    return None
                raise ValidationException( 
                   _("%(context)s: Input number required") %
                   {'context' : context}, 
                   _("Input number required: context=%(context)s, input=%(input)s") % 
                   {'context' :context,
                    'input' : input_}, 
                   context )
                        
            # canonicalize
            try:
                canonical = self.encoder.canonicalize( input_ )
            except EncodingException, extra:
                raise ValidationException( 
                   _("%(context)s: Invalid number input. Encoding problem detected.") %
                   {'context' : context}, 
                   _("Error canonicalizing user input"), 
                   extra, 
                   context )
                
            if self.min_value > self.max_value:
                raise ValidationException( 
                   _("%(context)s: Invalid number input: context") % 
                   {'context' : context}, 
                   _("Validation parameter error for number: max_value ( %(max_value)s ) must be greater than min_value ( %(min_value)s ) for %(context)s") % 
                   {'max_value' : self.max_value,
                    'min_value' : self.min_value,
                    'context' : context}, 
                   context )
                
            # must be able to convert to intended type
            try:
                typed_value = self.num_type(canonical)
            except ValueError, extra:
                raise ValidationException( 
                   _("%(context)s: Invalid number input") % 
                   {'context' : context}, 
                   _("Invalid number input format: context=%(context)s, input=%(input)s") %
                   {'context' : context,
                   'input' : input_}, 
                  None, 
                  context)
                
            # validate min and max
            if not self.min_value <= typed_value <= self.max_value:
                raise ValidationException( 
                   _("Invalid number input must be between %(min_value)s and %(max_value)s: context=%(context)s") % 
                   {'context' : context,
                    'min_value' : self.min_value,
                    'max_value' : self.max_value}, 
                   _("Invalid number input must be between %(min_value)s and %(max_value)s: context=%(context)s, input=%(input)s") % 
                   {'context' : context,
                    'min_value' : self.min_value,
                    'max_value' : self.max_value,
                    'input' : input_}, 
                   context )

            return typed_value
        except ValidationException, extra:
            if error_list is not None:
                error_list[context] = extra
            else:
                raise
            
        return None