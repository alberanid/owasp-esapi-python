#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: Syntax and semantic validation of a credit card number.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

from esapi.core import ESAPI
from esapi.translation import _

from esapi.reference.validation.base_validation_rule import BaseValidationRule
from esapi.reference.validation.string_validation_rule import StringValidationRule

from esapi.exceptions import ValidationException

CC_MAX_LENGTH = 19

class CreditCardValidationRule(BaseValidationRule):
    """
    This validator is used to perform syntax and semantic validation of a credit
    card number using the Luhn algorithm.
    """
    def __init__(self, type_name, encoder):
        BaseValidationRule.__init__(self, type_name, encoder)
        self.ccrule = self.get_cc_rule(encoder)
        
    def get_cc_rule(self, encoder):
        pattern = ESAPI.security_configuration().get_validation_pattern("CreditCard")
        ccr = StringValidationRule("ccrule", encoder, pattern)
        ccr.set_maximum_length(CC_MAX_LENGTH)
        ccr.set_allow_none(False)
        return ccr
        
    def get_valid(self, context, input_, error_list=None):
        try:
            # check null
            if input_ is None or len(input_) == 0:
                if self.allow_none:
                    return None
                raise ValidationException( 
                   _("%(context)s: Input credit card required") % 
                   {'context' : context}, 
                   _("Input credit card required: context=%(context)s, input=%(input)s") % 
                   {'context' : context,
                    'input' : input_}, 
                   context )
                        
            # canonicalize
            canonical = self.ccrule.get_valid(context, input_)
            
            digits_only = ''.join([char for char in canonical if char.isdigit()])
            
            # Luhn alogrithm checking
            sum_ = 0
            times_two = False
            for digit in reversed(digits_only):
                digit = int(digit)
                assert 0 <= digit <= 9
                if times_two:
                    digit *= 2
                    if digit > 9:
                        digit -= 9
                sum_ += digit
                times_two = not times_two
            if (sum_ % 10) != 0:
                raise ValidationException( 
                   _("%(context)s: Invalid credit card input") % 
                   {'context' : context}, 
                   _("Invalid credit card input. Credit card number did not pass Luhn test: context=%(context)s") % 
                   {'context' : context}, 
                  context )
                
            return digits_only
        except ValidationException, extra:
            if error_list is not None:
                error_list[context] = extra
            else:
                raise
            
        return None
        
