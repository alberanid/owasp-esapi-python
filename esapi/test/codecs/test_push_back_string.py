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

import esapi.core
from esapi.codecs.push_back_string import PushbackString

class PushbackStringTest(unittest.TestCase):
    
    def __init__(self, test_name=""):
        """
        Instantiates a new EncoderTest test.
        
        @param test_name the test name
        """
        unittest.TestCase.__init__(self, test_name)
        
    def test_next(self):
        obj = PushbackString("abc")
        self.assertEquals('a', obj.next())
        self.assertEquals('b', obj.next())
        self.assertEquals('c', obj.next())
        
    def test_index(self):
        obj = PushbackString("abcdef")
        
        self.assertEquals(0, obj.index())
        
        next1 = obj.next()
        self.assertEquals('a', next1)
        self.assertEquals(1, obj.index())
        
        next2 = obj.next()
        self.assertEquals('b', next2)
        self.assertEquals(2, obj.index())
        
    def test_peek(self):
        obj = PushbackString("abc")
        
        self.assertEquals('a', obj.peek())
        obj.next()
        self.assertEquals('b', obj.peek())
        
        self.assertFalse(obj.peek('c'))
        self.assertTrue(obj.peek('b'))
        
    def test_has_next(self):
        obj = PushbackString("abc")
        
        self.assertTrue(obj.has_next())
        obj.next()
        self.assertTrue(obj.has_next())
        obj.next()
        self.assertTrue(obj.has_next())
        obj.next()
        self.assertFalse(obj.has_next())
        
    def test_next_hex_octal(self):
        obj = PushbackString("a0q9")
        
        self.assertEquals('a', obj.next_hex())
        self.assertEquals('0', obj.next_octal())
        
        self.assertEquals(2, obj.index())
        self.assertEquals('q', obj.peek())
        self.assertEquals(None, obj.next_hex())
        self.assertEquals(3, obj.index())
        
        self.assertEquals('9', obj.peek())
        self.assertEquals(None, obj.next_octal())
            
    def test_mark_and_reset(self):
        obj = PushbackString("abcde")
        
        # Test reset to initial 0
        self.assertEquals(0, obj.index())
        self.assertEquals('a', obj.next())
        self.assertEquals(1, obj.index())
        obj.reset()
        self.assertEquals(0, obj.index())
        self.assertEquals('a', obj.next())
        obj.reset()
        
        obj.next()
        obj.next()
        self.assertEquals(2, obj.index())
        obj.mark()
        obj.reset()
        self.assertEquals(2, obj.index())
        self.assertEquals('c', obj.next())
        self.assertEquals(3, obj.index())
        obj.reset()
        self.assertEquals(2, obj.index())
        self.assertEquals('c', obj.next())        
    
if __name__ == "__main__":
    unittest.main()