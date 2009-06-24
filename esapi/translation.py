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

import gettext
import os

LOCALEDIR = 'conf\locale'
CWD = os.getcwd()
POS = CWD.find('esapi')
PATH = CWD[:POS] + 'esapi\\' + LOCALEDIR

TRANSLATION = gettext.translation('esapi', PATH, fallback=True)
_ = TRANSLATION.ugettext
