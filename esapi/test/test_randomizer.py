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

# Todo
# Change ascii_letters once Encoder is implemented
# Change testGetRandomString when Codec is written

import unittest
import sys

from esapi.core import ESAPI

class RandomzerTest(unittest.TestCase):
    
    alpha_numerics = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

    def __init__(self, test_name=""):
        """
        Instantiates a new Randomizer test.
        
        @param test_name the test name
        """
        unittest.TestCase.__init__(self, test_name)
            
    def suite(self):
        """
        Suite.
        
        @return the test
        """
        suite = unittest.makeSuite(Randomizer,'test')
        
        return suite
    
    def test_get_random_string(self):
        length = 20
        instance = ESAPI.randomizer()
        for i in range (100):
            result = instance.get_random_string(length, self.alpha_numerics)
            #print result
            # for char is result:
                # if !Codec.containsCharacter( result[j], self.alpha_numerics):
                    # self.fail()
                    
            self.assertEquals(length, len(result))
    
    def test_get_random_integer(self):
        min_ = -20
        max_ = 100
        instance = ESAPI.randomizer()
        min_result = max_result = ( max_ - min_ ) / 2
        for i in range(100):
            result = instance.get_random_integer(min_, max_)
            #print result
            if result < min_result: 
                min_result = result
            if result > max_result: 
                max_result = result
        
        assert min_result >= min_ and max_result <= max_
    
    def test_get_random_float(self):
        min_ = -20.5234
        max_ = 100.12124
        instance = ESAPI.randomizer()
        min_result = max_result = ( max_ - min_ ) / 2
        for i in range(100):
            result = instance.get_random_float(min_, max_)
            #print result
            if result < min_result: 
                min_result = result
            if result > max_result: 
                max_result = result
        
        assert min_result >= min_ and max_result <= max_
  
    def test_get_random_guid(self):
        instance = ESAPI.randomizer()
        guids = []
        for i in range(100):
            guid = instance.get_random_guid()
            #print guid
            self.assertEquals(36, len(guid)) # Check length
            self.assertEquals('4', guid[14]) # Check version 4
            assert guid[19] in '89ab' # Check high bits
            if guid in guids: 
                self.fail()
            guids.append(guid)
    
    
if __name__ == "__main__":
    unittest.main()

