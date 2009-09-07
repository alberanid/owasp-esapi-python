#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: The ValidationErrorList is a specialized dictionary to collect 
    ValidationExceptions.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

from esapi.translation import _

class ValidationErrorList(dict):
    """
    The ValidationErrorList is a specialized dictionary to collect 
    ValidationExceptions. The main difference is that a context key
    may not be overwritten with a new ValidationException.
    """
    def __setitem__(self, context, validation_exception):
        if context is None:
            raise RuntimeError(_("context parameter cannot be None"))
        if validation_exception is None:
            raise RuntimeError(_("validation_exception parameter cannot be None"))
        if self.has_key(context):
            raise RuntimeError(_("Context %(context)s already exists, must be unique") % 
                {'context' : context})
            
        dict.__setitem__(self, context, validation_exception)