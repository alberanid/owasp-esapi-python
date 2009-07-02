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

from esapi.core import ESAPI

from esapi.validation_error_list import ValidationErrorList

class ValidatorTest(unittest.TestCase):

    def __init__(self, test_name=""):
        """
        Instantiates a new Validator test.
        
        @param test_name the test name
        """
        unittest.TestCase.__init__(self, test_name)
    
    def test_get_valid_cc(self):
        instance = ESAPI.validator()
        errors = ValidationErrorList()
        
        self.assertTrue(instance.is_valid_credit_card("cctest1", "1234 9876 0000 0008", False));
        self.assertTrue(instance.is_valid_credit_card("cctest2", "1234987600000008", False));
        self.assertFalse(instance.is_valid_credit_card("cctest3", "12349876000000081", False));
        self.assertFalse(instance.is_valid_credit_card("cctest4", "4417 1234 5678 9112", False));
        
        instance.get_valid_credit_card("cctest5", "1234 9876 0000 0008", False, errors);
        self.assertEquals( 0, len(errors) );
        instance.get_valid_credit_card("cctest6", "1234987600000008", False, errors);
        self.assertEquals( 0, len(errors) );
        instance.get_valid_credit_card("cctest7", "12349876000000081", False, errors);
        self.assertEquals( 1, len(errors) );
        instance.get_valid_credit_card("cctest8", "4417 1234 5678 9112", False, errors);
        self.assertEquals( 2, len(errors) );
    
    
if __name__ == "__main__":
    unittest.main()

