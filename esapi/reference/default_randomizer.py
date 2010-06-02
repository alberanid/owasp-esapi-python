#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: Reference implementation of the Randomizer interface.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

"""
Security Rationale:

random.SystemRandom uses os.urandom(), a proxy to an OS based source of 
entropy, to generate pseudo random numbers. On UNIX-like system, os.urandom() 
will use /dev/urandom. On Windows, it will use CryptGenRandom. If an OS level 
source of entropy is not found, a NotImplementedError() will be thrown.
"""

# Todo

from random import SystemRandom

from esapi.core import ESAPI
from esapi.logger import Logger
from esapi.randomizer import Randomizer
from esapi.translation import _
from esapi.encoder import Encoder
from esapi.conf.constants import MAX_INTEGER, MIN_INTEGER, MAX_FLOAT, MIN_FLOAT

class DefaultRandomizer(Randomizer):
    def __init__(self):
        Randomizer.__init__(self)
        self.secure_random = SystemRandom()
        self.logger = ESAPI.logger("Randomizer")

    def get_random_string(self, length, character_set):
        ret = []
        for i in range(length):
            ret.append( self.get_random_choice(character_set) )
        return ''.join(ret)

    def get_random_boolean(self):
        return self.get_random_choice([True, False])

    def get_random_integer(self, min_=MIN_INTEGER, max_=MAX_INTEGER):
        return self.secure_random.randint(min_, max_)

    def get_random_filename(self, extension):
        filename = self.get_random_string(12, Encoder.CHAR_ALPHANUMERICS) + \
                   "." + extension
        self.logger.debug(Logger.SECURITY_SUCCESS, 
                          _("Generated a new random filename: ") + filename)
        return filename
        
    def get_random_float(self, min_=MIN_FLOAT, max_=MAX_FLOAT):
        return self.secure_random.uniform(min_, max_)

    def get_random_guid(self):
        parts = [None] * 5
        parts[0] = self.get_random_string(8, Encoder.CHAR_LOWER_HEX)
        parts[1] = self.get_random_string(4, Encoder.CHAR_LOWER_HEX)
        # Sets GUID version to 4 
        parts[2] = '4' + self.get_random_string(3, Encoder.CHAR_LOWER_HEX)
        # Sets high bits
        parts[3] = self.get_random_choice('89ab') + \
                   self.get_random_string(3, Encoder.CHAR_LOWER_HEX) 
        parts[4] = self.get_random_string(12, Encoder.CHAR_LOWER_HEX)
        return '-'.join(parts)
                    
    def get_random_choice(self, seq):
        return self.secure_random.choice(seq)
        
