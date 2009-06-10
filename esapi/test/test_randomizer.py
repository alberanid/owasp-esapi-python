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
# Change ascii_letters once Encoder is implemented
# Change testGetRandomString when Codec is written

import unittest
import sys

import esapi.core as core

class RandomzerTest(unittest.TestCase):
    
    alpha_numerics = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

    def __init__(self, testName=""):
        """
        Instantiates a new Randomizer test.
        
        @param testName the test name
        """
        unittest.TestCase.__init__(self, testName)
        
    def suite(self):
        """
        Suite.
        
        @return the test
        """
        suite = unittest.makeSuite(Randomizer,'test')
        
        return suite
    
    def testGetRandomString(self):
        length = 20
        instance = core.getRandomizer()
        for i in range (100):
            result = instance.getRandomString(length, self.alpha_numerics)
            #print result
            # for char is result:
                # if !Codec.containsCharacter( result[j], self.alpha_numerics):
                    # self.fail()
                    
            self.assertEquals(length, len(result))
    
    def testGetRandomInteger(self):
        min = -20
        max = 100
        instance = core.getRandomizer()
        minResult = maxResult = ( max - min ) / 2
        for i in range(100):
            result = instance.getRandomInteger(min, max)
            #print result
            if result < minResult: minResult = result
            if result > maxResult: maxResult = result
        
        assert minResult >= min and maxResult <= max
    
    def testGetRandomFloat(self):
        min = -20.5234
        max = 100.12124
        instance = core.getRandomizer()
        minResult = maxResult =( max - min ) / 2
        for i in range(100):
            result = instance.getRandomFloat(min, max)
            #print result
            if result < minResult: minResult = result
            if result > maxResult: maxResult = result
        
        assert minResult >= min and maxResult <= max
  
    def testGetRandomGUID(self):
        instance = core.getRandomizer()
        list = []
        for i in range(100):
            guid = instance.getRandomGUID()
            #print guid
            self.assertEquals(36, len(guid)) # Check length
            self.assertEquals('4', guid[14]) # Check version 4
            assert guid[19] in '89ab' # Check high bits
            if guid in list: self.fail()
            list.append(guid)
    
    
if __name__ == "__main__":
    unittest.main()

