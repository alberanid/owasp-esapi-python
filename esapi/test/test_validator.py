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
    
    def test_get_valid_date(self):
        instance = ESAPI.validator()
        errors = ValidationErrorList()
        
        self.assertTrue(instance.get_valid_date("datetest1", "June 23, 1967", "%B %d, %Y", False ))
        instance.get_valid_date("datetest2", "freakshow", "%B %d, %Y", False, errors )
        self.assertEquals( 1, len(errors) )
        
        instance.get_valid_date( "test", "June 32, 2008", "%B %d, %Y", False, errors )
        self.assertEquals( 2, len(errors) )
        
    def test_is_valid_integer(self):
        instance = ESAPI.validator();
        # testing negative range
        self.assertFalse(instance.is_valid_integer("test", "-4", 1, 10, False));
        self.assertTrue(instance.is_valid_integer("test", "-4", -10, 10, False));
        # testing null value
        self.assertTrue(instance.is_valid_integer("test", None, -10, 10, True));
        self.assertFalse(instance.is_valid_integer("test", None, -10, 10, False));
        # testing empty string
        self.assertTrue(instance.is_valid_integer("test", "", -10, 10, True));
        self.assertFalse(instance.is_valid_integer("test", "", -10, 10, False));
        # testing improper range
        self.assertFalse(instance.is_valid_integer("test", "5", 10, -10, False));
        # testing non-integers
        self.assertFalse(instance.is_valid_integer("test", "4.3214", -10, 10, True));
        self.assertFalse(instance.is_valid_integer("test", "-1.65", -10, 10, True));
        # other testing
        self.assertTrue(instance.is_valid_integer("test", "4", 1, 10, False));
        self.assertTrue(instance.is_valid_integer("test", "400", 1, 10000, False));
        self.assertTrue(instance.is_valid_integer("test", "400000000", 1, 400000000, False));
        self.assertFalse(instance.is_valid_integer("test", "4000000000000", 1, 10000, False));
        self.assertFalse(instance.is_valid_integer("test", "alsdkf", 10, 10000, False));
        self.assertFalse(instance.is_valid_integer("test", "--10", 10, 10000, False));
        self.assertFalse(instance.is_valid_integer("test", "14.1414234x", 10, 10000, False));
        self.assertFalse(instance.is_valid_integer("test", "Infinity", 10, 10000, False));
        self.assertFalse(instance.is_valid_integer("test", "-Infinity", 10, 10000, False));
        self.assertFalse(instance.is_valid_integer("test", "NaN", 10, 10000, False));
        self.assertFalse(instance.is_valid_integer("test", "-NaN", 10, 10000, False));
        self.assertFalse(instance.is_valid_integer("test", "+NaN", 10, 10000, False));
        self.assertFalse(instance.is_valid_integer("test", "1e-6", -999999999, 999999999, False));
        self.assertFalse(instance.is_valid_integer("test", "-1e-6", -999999999, 999999999, False));
        
    def test_get_valid_integer(self):
        instance = ESAPI.validator()
        errors = ValidationErrorList()
        
        # no tests yet
if __name__ == "__main__":
    unittest.main()

