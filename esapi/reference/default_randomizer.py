"""
OWASP Enterprise Security API (ESAPI)
 
This file is part of the Open Web Application Security Project (OWASP)
Enterprise Security API (ESAPI) project. For details, please see
<a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
Copyright (c) 2009 - The OWASP Foundation

The ESAPI is published by OWASP under the BSD license. You should read and accept the
LICENSE before you use, modify, and/or redistribute this software.

@author Craig Younkins (craig.younkins@owasp.org)
"""

"""
Security Rationale:

random.SystemRandom uses os.urandom(), a proxy to an OS based source of entropy, to generate
pseudo random numbers. On UNIX-like system, os.urandom() will use /dev/urandom. On Windows, 
it will use CryptGenRandom. If an OS level source of entropy is not found, a NotImplementedError()
will be thrown.
"""

# Todo
# Change alpha_numerics and hex once Encoder is written

from random import SystemRandom

import esapi.core
from esapi.logger import Logger
from esapi.randomizer import Randomizer

class DefaultRandomizer(Randomizer):
    alpha_numerics = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    hex = '0123456789abcdef'

    def __init__(self):
        self.secureRandom = SystemRandom()
        self.logger = esapi.core.getLogger("Randomizer")

    def getRandomString(self, length, characterSet):
        ret = ""
        for i in range(length):
            ret += self.getRandomChoice(characterSet)
        return ret

    def getRandomBoolean(self):
        return self.getRandomChoice([True, False])

    def getRandomInteger(self, min, max):
        return self.secureRandom.randint(min, max)

    def getRandomFilename(self, extension):
        fn = self.getRandomString(12, self.alpha_numerics) + "." + extension
        self.logger.debug(Logger.SECURITY_SUCCESS, "Generated a new random filename: " + fn)
        return fn
        
    def getRandomFloat(self, min, max):
        return self.secureRandom.uniform(min, max)

    def getRandomGUID(self):
        parts = [None] * 5
        parts[0] = self.getRandomString(8, self.hex)
        parts[1] = self.getRandomString(4, self.hex)
        parts[2] = '4' + self.getRandomString(3, self.hex) # Sets GUID version to 4
        parts[3] = self.getRandomChoice('89ab') + self.getRandomString(3, self.hex) # Sets high bits
        parts[4] = self.getRandomString(12, self.hex)
        return '-'.join(parts)
                    
    def getRandomChoice(self, seq):
        return self.secureRandom.choice(seq)
        


