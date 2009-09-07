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

from esapi.codecs.mysql import MySQLCodec

class MySQLCodecTest(unittest.TestCase):

    mysql_known_values = ( 
                     ('ac', 'ac'),
                     ('<', '\\<'),
                     (unichr(0), "\\0"),
                     ("'", "\\'"),
                     ('"', '\\"'),
                     ("\t", "\\t"),
                     ("\n", "\\n"),
                     ("\\", "\\\\"),
                     ("%", "\\%"),
                     ("_", "\\_"),
                    )
                     
    ansi_known_values = (
                    ('test', 'test'),
                    ("'", "''"),
                    )
                     
    
    def __init__(self, test_name=""):
        """
        Instantiates a new MySQLCodecTest test.
        
        @param test_name the test name
        """
        unittest.TestCase.__init__(self, test_name)
        self.mysql_codec = MySQLCodec(MySQLCodec.MYSQL_MODE)
        self.ansi_codec = MySQLCodec(MySQLCodec.ANSI_MODE)
        
    def test_encoding(self):
        # Test mysql mode first
        for plain, encoded in self.mysql_known_values:
            result = self.mysql_codec.encode('', plain) # No immunes
            self.assertEquals(encoded, result)
            
        # Test ansi mode second
        for plain, encoded in self.ansi_known_values:
            result = self.ansi_codec.encode('', plain) # No immunes
            self.assertEquals(encoded, result)
            
    def test_decoding(self):
        # Test mysql mode first
        for decoded, encoded in self.mysql_known_values:
            result = self.mysql_codec.decode(encoded)
            self.assertEquals(decoded, result)

        # Test ansi mode second
        for decoded, encoded in self.ansi_known_values:
            result = self.ansi_codec.decode(encoded)
            self.assertEquals(decoded, result)
            
    def test_immunes(self):
        immune = '~_-.'
        plain = immune[:]
        result = self.mysql_codec.encode(immune, plain)
        self.assertEquals(result, plain)
        
        decoded = self.mysql_codec.decode(result)
        self.assertEquals(decoded, plain)
    
if __name__ == "__main__":
    unittest.main()