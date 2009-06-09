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

import uuid
from random import SystemRandom

import esapi.core
from esapi.logger import Logger
from esapi.randomizer import Randomizer

class DefaultRandomizer(Randomizer):
    ascii_letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

    def __init__(self):
        self.secureRandom = SystemRandom()
        self.logger = esapi.core.getLogger("Randomizer")

    def getRandomString(self, length, characterSet):
        ret = ""
        for i in range(length):
            ret += self.secureRandom.choice(characterSet)

    def getRandomBoolean(self):
        return self.secureRandom.choice([True, False])

    def getRandomNumber(self, min, max):
        return self.secureRandom.randint(min, max)

    def getRandomFilename(self, extension):
        fn = self.getRandomString(12, self.ascii_letters) + "." + extension
        self.logger.debug(Logger.SECURITY_SUCCESS, "Generated a new random filename: " + fn)
        return fn

    def getRandomGUID(self):
        return str(uuid.uuid4())


