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

class EncoderTest(unittest.TestCase):
    
    def __init__(self, test_name=""):
        """
        Instantiates a new EncoderTest test.
        
        @param test_name the test name
        """
        unittest.TestCase.__init__(self, test_name)
        
    def test_encode_for_url(self):
        instance = esapi.core.get_encoder()
        self.assertEquals(None, instance.encode_for_url(None))
        self.assertEquals("%3Cscript%3E", instance.encode_for_url("<script>"))
        
    def test_decode_from_url(self):
        instance = esapi.core.get_encoder()
        self.assertEquals(None, instance.decode_from_url(None))
        self.assertEquals("<script>", instance.decode_from_url("%3Cscript%3E"))
        self.assertEquals("     ", instance.decode_from_url("+++++") )
        
        try:
            instance.decode_from_url( "%3xridiculous" )
            self.fail()
        except:
            # Expected
            pass
            
    
if __name__ == "__main__":
    unittest.main()