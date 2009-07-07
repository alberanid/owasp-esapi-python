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

from esapi.validator import Validator
from esapi.core import ESAPI

from esapi.codecs.html_entity import HTMLEntityCodec
from esapi.codecs.percent import PercentCodec

from esapi.exceptions import ValidationException

from esapi.reference.default_encoder import DefaultEncoder

from esapi.reference.validation.credit_card_validation_rule import CreditCardValidationRule
from esapi.reference.validation.date_validation_rule import DateValidationRule
from esapi.reference.validation.number_validation_rule import NumberValidationRule

class DefaultValidator(Validator):
    """
    Reference implementation of the Validator interface. This implementation
    relies on the ESAPI Encoder, re's regex,
    and several other classes to provide basic validation functions. This library
    has a heavy emphasis on whitelist validation and canonicalization. All double-encoded
    characters, even in multiple encoding schemes, such as <PRE>&amp;lt;</PRE> or
    <PRE>%26lt;<PRE> or even <PRE>%25%26lt;</PRE> are disallowed.
    """
    
    MAX_PARAMETER_NAME_LENGTH = 100
    MAX_PARAMETER_VALUE_LENGTH = 65535
    
    def __init__(self, encoder=None):
        Validator.__init__(self)
        if encoder:
            self.encoder = encoder
        else:
            self.encoder = ESAPI.encoder()
            
        self.rules = {}
        
#        file_codecs = [HTMLEntityCodec(), PercentCodec()]
#        file_encoder = DefaultEncoder(file_codecs)
#        self.file_validator = DefaultValidator( file_encoder )
        
    def add_rule(self, rule):
        """
        Add a validation rule using the "type name" of the rule as the key.
        """
        self.rules[ rule.get_type_name() ] = rule
        
    def get_rule(self, name):
        """
        Get a validation rule using the given "type name" of the rule as the 
        key.
        """
        return self.rules.get( name, None )
        
    def is_valid_credit_card(self, context, input_, allow_none):
        """
        Returns true if input is a valid credit card.
        """
        try:
            self.get_valid_credit_card( context, input_, allow_none )
            return True
        except ValidationException, extra:
            return False
            
    def get_valid_credit_card(self, context, input_, allow_none, errors=None):
        """
        Returns a canonicalized and validated credit card number as a String. 
        Invalid input will generate a descriptive ValidationException, and 
        input that is clearly an attack will generate a descriptive 
        IntrusionException. 
        """
        ccvr = CreditCardValidationRule("creditcard", self.encoder)
        ccvr.set_allow_none(allow_none)
        return ccvr.get_valid(context, input_, errors)
    
    def is_valid_date(self, context, input_, format, allow_none):
        """
        Returns true if input is a valid date.
        """
        try:
            self.get_valid_date( context, input_, format, allow_none )
            return True
        except ValidationException, extra:
            return False
            
    def get_valid_date(self, context, input_, format, allow_none, errors=None):
        """
        Returns a valid date as a Date. Invalid input will generate a 
        descriptive ValidationException, and input that is clearly an attack 
        will generate a descriptive IntrusionException.
        """
        dvr = DateValidationRule("SimpleDate", self.encoder, format)
        dvr.set_allow_none(allow_none)
        return dvr.get_valid(context, input_, errors)
        
    def is_valid_number(self, context, num_type, input_, min_value, max_value, allow_none):
        """
        Returns true if the input is a valid instance of the given type, and
        within the specified range.
        """
        try:
            self.get_valid_number(context, num_type, input_, min_value, max_value, allow_none)
            return True
        except ValidationException, extra:
            return False
            
    def get_valid_number(self, context, num_type, input_, min_value, max_value, allow_none, errors=None):
        """
        Returns a valid number of given num_type. Invalid input will generate a
        descriptive ValidationException, and input that is clearly an attack 
        will generate a descriptive IntrusionException.
        """
        nvr = NumberValidationRule("number", num_type, self.encoder, min_value, max_value)
        nvr.set_allow_none(allow_none)
        return nvr.get_valid(context, input_, errors)