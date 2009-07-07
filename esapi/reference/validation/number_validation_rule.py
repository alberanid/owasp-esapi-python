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

from esapi.reference.validation.base_validation_rule import BaseValidationRule

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
            # check null
            if input_ is None or len(input_) == 0:
                if self.allow_none:
                    return None
                raise ValidationException( context + ": Input number required", 
                        "Input number required: context=" + context + ", input=''", context )
                        
            # canonicalize
            try:
                canonical = self.encoder.canonicalize( input_ )
            except EncodingException, extra:
                raise ValidationException( context + ": Invalid number input. Encoding problem detected.", 
                                           "Error canonicalizing user input", extra, context)
                
            if self.min_value > self.max_value:
                raise ValidationException(context + ": Invalid number input: context", "Validation parameter error for number: max_value ( " + str(self.max_value) + ") must be greater than min_value ( " + str(self.min_value) + ") for " + context, context )
                
            # must be able to convert to intended type
            try:
                typed_value = self.num_type(canonical)
            except ValueError, extra:
                raise ValidationException(context + ": Invalid number input", "Invalid number input format: context=" + context + ", input=" + input_, None, context)
                
            # validate min and max
            if not self.min_value <= typed_value <= self.max_value:
                raise ValidationException( "Invalid number input must be between " + str(self.min_value) + " and " + str(self.max_value) + ": context=" + context, "Invalid number input must be between " + str(self.min_value) + " and " + str(self.max_value) + ": context=" + context + ", input=" + input_, context )

            return typed_value
        except ValidationException, extra:
            if error_list is not None:
                error_list[context] = extra
            else:
                raise
            
        return None