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

# Todo
# Change hash after Encoder and Base64 encoder have been written

import hashlib

import esapi.core
from esapi.encryptor import Encryptor

class DefaultEncryptor(Encryptor):
    def __init__(self):
        self.hashAlgorithm = esapi.core.getSecurityConfiguration().getHashAlgorithm();
        self.hashIterations = esapi.core.getSecurityConfiguration().getHashIterations();

    def hash(self, plaintext, salt, iterations=None):
        if iterations is None: iterations = self.hashIterations
    
        try:
            digest = hashlib.new(self.hashAlgorithm)
            digest.update(esapi.core.getSecurityConfiguration().getMasterSalt())
            digest.update(salt)
            digest.update(plaintext)
            
            bytes = digest.digest()
            for i in range(self.hashIterations):
                digest = hashlib.new(self.hashAlgorithm)
                digest.update(bytes)
                bytes = digest.digest()
                
            import base64
            encoded = base64.b64encode(bytes)
            return encoded
            
        except ValueError, e:
            raise EncryptionException, "Internal Error - Can't find hash algorithm " + self.hashAlgorithm
        
        
    def encrypt(self, plaintext):
        raise NotImplementedError()

    def decrypt(self, ciphertext):
        raise NotImplementedError()

    def sign(self, data):
        raise NotImplementedError()

    def verifySignature(self, signature, data):
        raise NotImplementedError()

    def seal(self, data, timestamp):
        raise NotImplementedError()

    def unseal(self, seal):
        raise NotImplementedError()

    def verifySeal(self, seal):
        raise NotImplementedError()

    def getRelativeTimeStamp(self, offset):
        raise NotImplementedError()

    def getTimeStamp(self):
        raise NotImplementedError()


