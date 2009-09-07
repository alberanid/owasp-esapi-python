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

from esapi.codecs.css import CSSCodec

class CSSCodecTest(unittest.TestCase):

    known_values = ( 
                     ('test', 'test'),
                     ('<', '\\3C '),
                     ('<script>', '\\3C script\\3E '),
                     ('!@$%()=+{}[]', '\\21 \\40 \\24 \\25 \\28 \\29 \\3D \\2B \\7B \\7D \\5B \\5D '),
                    )
                     
    known_encode_only = ( 
                          
                        ) 
                     
    known_decode_only = ( 
                          ('<', '\\<'),
                          ('<', '\\3c'),
                          # from http://dbaron.org/css/test/parsing3
                          ('two', '\\74 wo'),
                          ('three', '\\000074hree'),
                          ('four', '\\000066 our'),
                          ('five', '\\66\\69 \\76\\65'),
                          ('six', '\\00073 \\i\\x'),
                          ('Color', '\\43 \\6F \\6c \\00006fr'),
                          ('9', '\\39'),
                          ('{}', '\\7b\\7d'),
                        )
                     
    
    def __init__(self, test_name=""):
        """
        Instantiates a new CSSCodecTest test.
        
        @param test_name the test name
        """
        unittest.TestCase.__init__(self, test_name)
        self.codec = CSSCodec()
        
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