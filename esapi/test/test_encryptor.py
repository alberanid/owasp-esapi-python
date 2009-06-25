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

import unittest

from esapi.core import ESAPI

class EncryptorTest(unittest.TestCase):
    """
    The Class EncryptorTest
    
    @author Craig Younkins (craig.younkins@owasp.org)
    """
    
    def __init__(self, test_name=""):
        """
        Instantiates a new Encryptor test.
        
        @param test_name the test name
        """
        unittest.TestCase.__init__(self, test_name)
    
    def test_hash(self):
        instance = ESAPI.encryptor()
        hash1 = instance.hash("test1", "salt")
        hash2 = instance.hash("test2", "salt")
        self.assertFalse(hash1 == hash2)
        hash3 = instance.hash("test", "salt1")
        hash4 = instance.hash("test", "salt2")
        self.assertFalse(hash3 == hash4)
        
    def test_encrypt(self):
        instance = ESAPI.encryptor()
        plaintext = "test1234"
        ciphertext = instance.encrypt(plaintext)
        result = instance.decrypt(ciphertext)
        self.assertEquals(plaintext, result)
        
    def test_decrypt(self):
        try:
            instance = ESAPI.encryptor()
            plaintext = "test123"
            ciphertext = instance.encrypt(plaintext)
            self.assertFalse(plaintext == ciphertext)
            result = instance.decrypt(ciphertext)
            self.assertEquals(plaintext, result)
        except:
            self.fail()
        
    def test_sign(self):
        pass
        
    def test_verify_signature(self):
        pass
        
    def test_seal(self):
        pass
        
    def test_verify_seal(self):
        pass

    def test_main(self):
        pass
    
if __name__ == "__main__":
    unittest.main()

