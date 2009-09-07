#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: An HTML validator using OWASP's AntiSamy.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

import re

from esapi.reference.validation.base_validation_rule import BaseValidationRule
from esapi.reference.default_encoder import DefaultEncoder

from esapi.exceptions import ValidationException
from esapi.exceptions import EncodingException

class HTMLValidationRule(BaseValidationRule):
    """
    This validator performs syntax validation of strings.
    """
