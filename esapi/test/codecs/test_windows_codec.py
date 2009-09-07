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

from esapi.codecs.windows import WindowsCodec

class WindowsCodecTest(unittest.TestCase):

    known_values = ( 
                     ('<', '^<'),
                     ('&', '^&'),
                     ('-', '^-'),
                     ('\\', '^\\'),
                     ('a', 'a'),
                    )
                     
    known_encode_only = ( 
                        (None, None),
                        ) 
                     
    known_decode_only = ( 
                        ('', None),
                        )
                     
    
    def __init__(self, test_name=""):
        """
        Instantiates a new WindowsCodec test.
        
        @param test_name the test name
        """
        unittest.TestCase.__init__(self, test_name)
        self.codec = WindowsCodec()
        
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