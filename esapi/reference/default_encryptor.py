#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: Reference implementation of the Encoder interface.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

# Todo
# Change hash after Encoder and Base64 encoder have been written

import hashlib
import Crypto.Cipher.AES
import Crypto.Cipher.DES
import Crypto.Cipher.DES3
import os

from esapi.core import ESAPI
from esapi.exceptions import EncryptionException
from esapi.encryptor import Encryptor
from esapi.translation import _

class DefaultEncryptor(Encryptor):
    encrypt_algorithm_map = {
        'AES' : Crypto.Cipher.AES,
        'DES' : Crypto.Cipher.DES,
        'DES3' : Crypto.Cipher.DES3}
    
    def __init__(self):
        Encryptor.__init__(self)
        # Hashing
        self.hash_algorithm = ESAPI.security_configuration().get_hash_algorithm()
        self.hash_iterations = ESAPI.security_configuration().get_hash_iterations()
        
        # Encryption
        encrypt_algorithm = ESAPI.security_configuration().get_encryption_algorithm()
        try:
            self.encrypt_algorithm_class = self.encrypt_algorithm_map[encrypt_algorithm]
        except KeyError:
            raise EncryptionException, _("Encryption Failure - Unknown algorithm: ") + self.encrypt_algorithm
        
        self.encryption_key_length = ESAPI.security_configuration().get_encryption_key_length()
        self.master_key = ESAPI.security_configuration().get_master_key()
        self.master_salt = ESAPI.security_configuration().get_master_salt()
        
        # Public key crypto
        self.signing_algorithm = ESAPI.security_configuration().get_digital_signature_algorithm()
        self.signing_key_length = ESAPI.security_configuration().get_digital_signature_key_length()
        self.signing_key_pair = ESAPI.security_configuration().get_digital_signature_key()
        

    def main(self):
        # Generate a new DSA key
        DSAKey = DSA.generate(self.signing_key_length, os.urandom)
        
    def hash(self, plaintext, salt, iterations=None):
        if iterations is None: 
            iterations = self.hash_iterations
    
        try:
            digest = hashlib.new(self.hash_algorithm)
            digest.update(self.master_salt)
            digest.update(salt)
            digest.update(plaintext)
            
            bytes = digest.digest()
            for i in range(self.hash_iterations):
                digest = hashlib.new(self.hash_algorithm)
                digest.update(bytes)
                bytes = digest.digest()
                
            encoded = ESAPI.encoder().encode_for_base64(bytes)
            return encoded
            
        except ValueError, e:
            raise EncryptionException, _("Internal Error - Can't find hash algorithm ") + self.hash_algorithm
        
    def encrypt(self, plaintext):
        encryptor = self.encrypt_algorithm_class.new(self.master_key)
        padded = self._pad(plaintext, encryptor.block_size)
        return encryptor.encrypt(padded)
            
    def _pad(self, text, block_size):
        """
        Pads the text according to RFC 1423 / PKCS5.
        First the number of bytes needed for padding is found.
        Then that number (say, n) is appended to the string n times.
        """
        n = block_size - ( len(text) % block_size )
        return text + unichr(n) * n
        
    def _unpad(self, text):
        """
        Unpads the text according to RFC 1423 / PKCS5.
        First the last byte of the string is taken. It is possibly
        the number of padded bytes. Working backwards, we test every character
        to ensure it is equal to the last byte, and it conforms
        to the padding scheme. It is possible, though improbable,
        that this will remove part of the data that looks like padding
        but is not.
        """
        pos_padding_len = text[-1]
        is_padding = True
        for char in text[-ord(pos_padding_len):]:
            if char != pos_padding_len:
                is_padding = False
                
        if is_padding:
            return text[:-ord(pos_padding_len)]

    def decrypt(self, ciphertext):
        crypt = self.encrypt_algorithm_class.new(self.master_key) 
        padded = crypt.decrypt(ciphertext)
        return self._unpad(padded)

    def sign(self, data):
        raise NotImplementedError()

    def verify_signature(self, signature, data):
        raise NotImplementedError()

    def seal(self, data, timestamp):
        raise NotImplementedError()

    def unseal(self, seal):
        raise NotImplementedError()

    def verify_seal(self, seal):
        raise NotImplementedError()

    def get_relative_timestamp(self, offset):
        raise NotImplementedError()

    def get_timestamp(self):
        raise NotImplementedError()


