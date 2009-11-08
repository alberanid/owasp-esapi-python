#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: Test suite for the Randomizer interface.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

# Todo

# Use esapi/test/conf instead of esapi/conf
# It is important that this is at the top, as it affects the imports below
# by loading the test configuration instead of the normal one.
# This should ONLY ever be used in the unit tests.
import esapi.test.conf

import unittest
import sys

from esapi.core import ESAPI
from esapi.encoder import Encoder

class RandomizerTest(unittest.TestCase):

    def __init__(self, test_name=""):
        """
        Instantiates a new Randomizer test.
        
        @param test_name: the test name
        """
        unittest.TestCase.__init__(self, test_name)
    
    def test_get_random_string(self):
        length = 20
        instance = ESAPI.randomizer()
        for i in range (100):
            result = instance.get_random_string(length, Encoder.CHAR_ALPHANUMERICS)
            for char in result:
                if char not in Encoder.CHAR_ALPHANUMERICS:
                    self.fail()
                    
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
            
    def test_get_random_boolean(self):
        instance = ESAPI.randomizer()
        trues = 0
        falses = 0
        for i in range(1000):
            ans = instance.get_random_boolean()
            if ans:
                trues += 1
            else:
                falses += 1
        if trues > 700 or falses > 700:
            print "There may be a problem with the randomizer."
            print "Got %s trues and %s falses" % (trues, falses)
            self.fail()
            
    def test_get_random_filename(self):
        instance = ESAPI.randomizer()
        for i in range(10):
            instance.get_random_filename('txt')
    
if __name__ == "__main__":
    unittest.main()

