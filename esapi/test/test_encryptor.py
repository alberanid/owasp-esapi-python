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

import unittest

import esapi.core

class EncryptorTest(unittest.TestCase):
    """
    The Class EncryptorTest
    
    @author Craig Younkins (craig.younkins@owasp.org)
    """
    
    def __init__(self, testName=""):
        """
        Instantiates a new Encryptor test.
        
        @param testName the test name
        """
        unittest.TestCase.__init__(self, testName)
        
    def suite(self):
        """
        Suite.
        
        @return the test
        """
        suite = unittest.makeSuite(Encryptor,'test')
        
        return suite
    
    def testHash(self):
        instance = esapi.core.getEncryptor()
        hash1 = instance.hash("test1", "salt")
        hash2 = instance.hash("test2", "salt")
        self.assertFalse(hash1 == hash2)
        hash3 = instance.hash("test", "salt1")
        hash4 = instance.hash("test", "salt2")
        self.assertFalse(hash3 == hash4)
        
    def testEncrypt(self):
        instance = esapi.core.getEncryptor()
        plaintext = "test1234"
        ciphertext = instance.encrypt(plaintext)
        result = instance.decrypt(ciphertext)
        self.assertEquals(plaintext, result)
        
    def testDecrypt(self):
        try:
            instance = esapi.core.getEncryptor()
            plaintext = "test123"
            ciphertext = instance.encrypt(plaintext)
            self.assertFalse(plaintext == ciphertext)
            result = instance.decrypt(ciphertext)
            self.assertEquals(plaintext, result)
        except:
            self.fail()
        
    def testSign(self):
        pass
        
    def testVerifySignature(self):
        pass
        
    def testSeal(self):
        pass
        
    def testVerifySeal(self):
        pass

    def testMain(self):
        pass
    
if __name__ == "__main__":
    unittest.main()

