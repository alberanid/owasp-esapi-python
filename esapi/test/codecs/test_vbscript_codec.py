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

from esapi.codecs.vbscript import VBScriptCodec

class VBScriptCodecTest(unittest.TestCase):

    known_values = ( 
                     ('<', 'chrw(60)'),
                     ('<script>', 'chrw(60)&"script"&chrw(62)'),
                     ('x !@$%()=+{}[]', 'x"&chrw(32)&chrw(33)&chrw(64)&chrw(36)&chrw(37)&chrw(40)&chrw(41)&chrw(61)&chrw(43)&chrw(123)&chrw(125)&chrw(91)&chrw(93)'),
                     ("alert('ESAPI test!')", "alert\"&chrw(40)&chrw(39)&\"ESAPI\"&chrw(32)&\"test\"&chrw(33)&chrw(39)&chrw(41)"),
                     ('jeff.williams@aspectsecurity.com', "jeff.williams\"&chrw(64)&\"aspectsecurity.com"),
                     ('test <> test', "test\"&chrw(32)&chrw(60)&chrw(62)&chrw(32)&\"test"),
                    )
                     
    known_encode_only = ( 
                        ) 
                     
    known_decode_only = ( 
                        ('<', '"<'),
                        ('chr(3)', 'chr(3)'), # malformed
                        ('chrw(333423)', 'chrw(333423)'), # malformed
                        ('chrw(60', 'chrw(60'), # malformed
                        )
                     
    
    def __init__(self, test_name=""):
        """
        Instantiates a new VBScript test.
        
        @param test_name the test name
        """
        unittest.TestCase.__init__(self, test_name)
        self.codec = VBScriptCodec()
        
    def test_encoding(self):
        for plain, encoded in self.known_values:
            result = self.codec.encode('', plain) # No immunes
            self.assertEquals(encoded, result)
            
        for plain, encoded in self.known_encode_only:
            result = self.codec.encode('', plain) # No immunes
            self.assertEquals(encoded, result)
    
    def test_decoding(self):
        for decoded, encoded in self.known_values:
            result = self.codec.decode(encoded)
            self.assertEquals(decoded, result)

        for decoded, encoded in self.known_decode_only:
            result = self.codec.decode(encoded)
            self.assertEquals(decoded, result)
            
    def test_immunes(self):
        immune = '~_-.'
        plain = immune[:]
        result = self.codec.encode(immune, plain)
        self.assertEquals(result, plain)
        
        decoded = self.codec.decode(result)
        self.assertEquals(decoded, plain)
        
    
if __name__ == "__main__":
    unittest.main()