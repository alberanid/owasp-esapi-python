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

from esapi.codecs.html_entity import HTMLEntityCodec

class HTMLEntityCodecTest(unittest.TestCase):

    known_values = ( 
                     ('test', 'test'),
                     ('<script>', '&lt;script&gt;'),
                     ('<', '&lt;'),
                     ('>', '&gt;'),
                     ('&', '&amp;'),
                     ('"', '&quot;'),
                     ('', ''),
                     (u'Δ', '&Delta;'),
                     (u'δ', '&delta;'),
                     ('dir&', 'dir&amp;'),
                     ('one&two', 'one&amp;two'),
                     (unichr(12345) + unichr(65533) + unichr(1244), unichr(12345) + unichr(65533) + unichr(1244)),
                    )
                     
    known_encode_only = ( 
      (unichr(2), ' '), # Illegal char
      ("a" + unichr(0) + "b" + unichr(4) + "c" + unichr(128) + "d" + unichr(150) + "e" +unichr(159) + "f" + unichr(9) + "g", "a b c d e f&#x9;g"),
      ("&lt;script&gt;", "&amp;lt&#x3b;script&amp;gt&#x3b;"),
      ("!@$%()=+{}[]", "&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;"),
      
                        ) 
                     
    known_decode_only = ( 
                          ('test!', '&#116;&#101;&#115;&#116;!'),
                          ('test!', '&#x74;&#x65;&#x73;&#x74;!'),
                          ('&jeff;', '&jeff;'),
                          ('&', '&'),
                          #('&#256;', '&#256;'), # unichr > 255
                          #('&#xFFF;', '&#xFFF;'), # unichr > 255
                          ('', None),
                        )
                     
    
    def __init__(self, test_name=""):
        """
        Instantiates a new HTMLEntityCodecTest test.
        
        @param test_name the test name
        """
        unittest.TestCase.__init__(self, test_name)
        self.codec = HTMLEntityCodec()
        
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