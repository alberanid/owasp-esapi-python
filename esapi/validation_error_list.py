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

class ValidationErrorList(dict):
    """
    The ValidationErrorList is a specialized dictionary to collect 
    ValidationExceptions. The main difference is that a context key
    may not be overwritten with a new ValidationException.
    """
    def __setitem__(self, context, validation_exception):
        if context is None:
            raise RuntimeError("context cannot be None")
        if validation_exception is None:
            raise RuntimeError("validation_exception cannot be None")
        if self.has_key(context):
            raise RuntimeError("Context (%s) already exists, must be unique" % context)
            
        dict.__setitem__(self, context, validation_exception)