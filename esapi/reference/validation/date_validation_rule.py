#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: A ValidationRule for dates. 
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

from datetime import datetime

from esapi.reference.validation.base_validation_rule import BaseValidationRule
from esapi.translation import _

from esapi.exceptions import ValidationException
from esapi.exceptions import EncodingException

class DateValidationRule(BaseValidationRule):
    """
    This date validator makes use of Python's 
    U{datetime.strptime<http://docs.python.org/library/datetime.html>}
    to validate that given dates conform to a format string.
    """
    def __init__(self, type_name, encoder, new_format):
        """
        @param new_format: Required formatting of date in string form, according 
               to Python's U{datetime.strptime<http://docs.python.org/library/datetime.html>}.
        """
        self.format = None
        
        BaseValidationRule.__init__(self, type_name, encoder)
        self.set_date_format(new_format)
        
    def set_date_format(self, new_format):
        """
        Sets the format string that input is tested against.
        @param new_format: Required formatting of date in string form, according 
               to Python's U{datetime.strptime<http://docs.python.org/library/datetime.html>}.
        """
        if new_format is None:
            raise RuntimeError("DateValidationRule.set_date_format requires a non-null DateFormat")
        self.format = new_format
        
    def get_valid(self, context, input_, error_list=None):
        try:
            # check null
            if input_ is None or len(input_) == 0:
                if self.allow_none:
                    return None
                raise ValidationException( 
                   _("%(context)s: Input date required") % 
                   {'context' : context}, 
                   _("Input date required: context=%(context)s, input=%(context)s") % 
                   {'context' : context,
                    'input' : input_}, 
                   context )
                        
            # canonicalize
            try:
                canonical = self.encoder.canonicalize( input_ )
            except EncodingException, extra:
                raise ValidationException( 
                   _("%(context): Invalid date input. Encoding problem detected.") % 
                   {'context' : context}, 
                   _("Error canonicalizing user input"), 
                   extra, 
                   context )
                
            try:
                date = datetime.strptime(canonical, self.format)
                return date
            except Exception, extra:
                raise ValidationException( 
                   _("%(context)s: Invalid date must follow the %(format)s format") % 
                   {'context' : context,
                    'format' : self.format}, 
                   _("Invalid date: context=%(context)s, format=%(format)s, input=%(input)s") %
                   {'context' : context,
                    'format' : self.format,
                    'input' : input_}, 
                   extra, 
                   context )
                
        except ValidationException, extra:
            if error_list is not None:
                error_list[context] = extra
            else:
                raise
            
        return None