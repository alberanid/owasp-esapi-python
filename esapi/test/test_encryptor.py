#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: Test suite for the Encryptor interface.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

# Use esapi/test/conf instead of esapi/conf
# It is important that this is at the top, as it affects the imports below
# by loading the test configuration instead of the normal one.
# This should ONLY ever be used in the unit tests.
import esapi.test.conf

import unittest
from datetime import datetime, timedelta
import time

from esapi.core import ESAPI
from esapi.encoder import Encoder
from esapi.exceptions import EncryptionException

class EncryptorTest(unittest.TestCase):
    """
    The Class EncryptorTest
    
    @author: Craig Younkins (craig.younkins@owasp.org)
    """
    
    def __init__(self, test_name=""):
        """
        Instantiates a new Encryptor test.
        
        @param test_name: the test name
        """
        unittest.TestCase.__init__(self, test_name)
    
    def test_hash(self):
        instance = ESAPI.encryptor()
        
        # Same salt, different texts
        hash1 = instance.hash("test1", "salt")
        hash2 = instance.hash("test2", "salt")
        self.assertFalse(hash1 == hash2)
        
        # Same text, different salts
        hash3 = instance.hash("test", "salt1")
        hash4 = instance.hash("test", "salt2")
        self.assertFalse(hash3 == hash4)
        
        # Same text, same salts
        hash3 = instance.hash("test", "salt1")
        hash4 = instance.hash("test", "salt1")
        self.assertTrue(hash3 == hash4)
        
    def test_crypt(self):
        instance = ESAPI.encryptor()
        
        def check(plaintext):
            ciphertext = instance.encrypt(plaintext)
            result = instance.decrypt(ciphertext)
            self.assertEquals(plaintext, result)
        
        # Example plaintext
        check("test1234")
        
        # 20 random strings
        for i in range(20):
            check(ESAPI.randomizer().get_random_string(40, Encoder.CHAR_ALPHANUMERICS))
            
    def test_sign_and_verify(self):
        instance = ESAPI.encryptor()
        
        def check(plaintext):
            sig = instance.sign(plaintext)
            self.assertTrue( instance.verify_signature(sig, plaintext) )
            self.assertFalse( instance.verify_signature(sig, "ridiculous") )
            self.assertFalse( instance.verify_signature("ridiculous", plaintext) )
            
        # Example plaintext
        check("test1234")
        
        # 20 random strings
        for i in range(20):
            check(ESAPI.randomizer().get_random_string(40, Encoder.CHAR_ALPHANUMERICS))
        
    def test_seal_unseal(self):
        instance = ESAPI.encryptor()
        plaintext = "THIS IS MY DATA"
        
        # Test with timedelta
        seal = instance.seal( plaintext, timedelta(minutes=1000) )
        data = instance.unseal(seal)
        self.assertEquals(plaintext, data)
        
        # Test with absolute datetime
        seal = instance.seal( plaintext, datetime.now() + timedelta(minutes=3) )
        data = instance.unseal(seal)
        self.assertEquals(plaintext, data)
        
        # Test with int
        future = datetime.now() + timedelta(minutes=3)
        seal = instance.seal( plaintext, time.mktime(future.timetuple()) )
        data = instance.unseal(seal)
        self.assertEquals(plaintext, data)
        
        # Unseal bad data
        self.assertRaises(EncryptionException, instance.unseal, "badseal")
        
    def test_verify_seal(self):
        instance = ESAPI.encryptor()
        plaintext = "ridiculous"
        seal = instance.seal( plaintext, timedelta(minutes=1000) )
        self.assertTrue(instance.verify_seal(seal))
        self.assertFalse(instance.verify_seal(plaintext))
        self.assertFalse(instance.verify_seal( instance.encrypt(plaintext) ) )
        self.assertFalse(instance.verify_seal( instance.encrypt("100:" + plaintext) ) )
        self.assertFalse(instance.verify_seal( instance.encrypt("100:random:" + plaintext) ) )
        self.assertFalse(instance.verify_seal( instance.encrypt("100:random:" + plaintext + ":badsig") ) )
          
    def test_main(self):
        pass
    
if __name__ == "__main__":
    unittest.main()

