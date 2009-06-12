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
import Crypto.Cipher.AES
import Crypto.Cipher.DES
import Crypto.Cipher.DES3
import os

import esapi.core
from esapi.encryptor import Encryptor

class EncryptionException(Exception): pass

class DefaultEncryptor(Encryptor):
    encryptAlgorithmMap = {
        'AES' : Crypto.Cipher.AES,
        'DES' : Crypto.Cipher.DES,
        'DES3' : Crypto.Cipher.DES3}
    
    def __init__(self):
        # Hashing
        self.hashAlgorithm = esapi.core.getSecurityConfiguration().getHashAlgorithm()
        self.hashIterations = esapi.core.getSecurityConfiguration().getHashIterations()
        
        # Encryption
        encryptAlgorithm = esapi.core.getSecurityConfiguration().getEncryptionAlgorithm()
        try:
            self.encryptAlgorithmClass = self.encryptAlgorithmMap[encryptAlgorithm]
        except KeyError:
            raise EncryptionException, "Encryption Failure - Unknown algorithm: " + self.encryptAlgorithm
        
        self.encryptionKeyLength = esapi.core.getSecurityConfiguration().getEncryptionKeyLength()
        self.masterKey = esapi.core.getSecurityConfiguration().getMasterKey()
        self.masterSalt = esapi.core.getSecurityConfiguration().getMasterSalt()
        
        # Public key crypto
        self.signingAlgorithm = esapi.core.getSecurityConfiguration().getDigitalSignatureAlgorithm()
        self.signingKeyLength = esapi.core.getSecurityConfiguration().getDigitalSignatureKeyLength()
        self.signingKeyPair = esapi.core.getSecurityConfiguration().getDigitalSignatureKey()
        

    def main(self):
        # Generate a new DSA key
        DSAKey = DSA.generate(self.signingKeyLength, os.urandom)
        
    def hash(self, plaintext, salt, iterations=None):
        if iterations is None: iterations = self.hashIterations
    
        try:
            digest = hashlib.new(self.hashAlgorithm)
            digest.update(self.masterSalt)
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
        encryptor = self.encryptAlgorithmClass.new(self.masterKey)
        padded = self._pad(plaintext, encryptor.block_size)
        return encryptor.encrypt(padded)
            
    def _pad(self, text, block_size):
        """
        Pads the text according to RFC 1423 / PKCS5.
        First the number of bytes needed for padding is found.
        Then that number (say, n) is appended to the string n times.
        """
        n = block_size - ( len(text) % block_size )
        return text + chr(n) * n
        
    def _unpad(self, text, block_size):
        """
        Unpads the text according to RFC 1423 / PKCS5.
        First the last byte of the string is taken. It is possibly
        the number of padded bytes. Working backwards, we test every character
        to ensure it is equal to the last byte, and it conforms
        to the padding scheme. It is possible, though improbable,
        that this will remove part of the data that looks like padding
        but is not.
        """
        n = text[-1]
        isPadding = True
        for char in text[-ord(n):]:
            if char != n:
                isPadding = False
                
        if isPadding:
            return text[:-ord(n)]

    def decrypt(self, ciphertext):
        crypt = self.encryptAlgorithmClass.new(self.masterKey) 
        padded = crypt.decrypt(ciphertext)
        return self._unpad(padded, crypt.block_size)

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


