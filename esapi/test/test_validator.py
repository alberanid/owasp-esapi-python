#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: Test suite for Validator interface.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

# Use esapi/test/conf instead of esapi/conf
# It is important that this is at the top, as it affects the imports below
# by loading the test configuration instead of the normal one.
# This should ONLY ever be used in the unit tests.
import esapi.test.conf

import unittest
import os
import os.path

from esapi.core import ESAPI

from esapi.codecs.html_entity import HTMLEntityCodec

from esapi.validation_error_list import ValidationErrorList
from esapi.reference.validation.string_validation_rule import StringValidationRule

class ValidatorTest(unittest.TestCase):

    def __init__(self, test_name=""):
        """
        Instantiates a new Validator test.
        
        @param test_name: the test name
        """
        unittest.TestCase.__init__(self, test_name)
             
    def test_is_valid_cc(self):
        instance = ESAPI.validator()
        
        self.assertTrue(instance.is_valid_credit_card("cctest1", "1234 9876 0000 0008", False))
        self.assertTrue(instance.is_valid_credit_card("cctest2", "1234987600000008", False))
        self.assertFalse(instance.is_valid_credit_card("cctest3", "12349876000000081", False))
        self.assertFalse(instance.is_valid_credit_card("cctest4", "4417 1234 5678 9112", False))
        
    def test_get_valid_cc(self):
        instance = ESAPI.validator()
        errors = ValidationErrorList()
        
        # Verify method strips spaces
        self.assertEquals("1234987600000008", instance.get_valid_credit_card("cctest1", "1234 9876 0000 0008", False ))
       
        instance.get_valid_credit_card("cctest5", "1234 9876 0000 0008", False, errors)
        self.assertEquals( 0, len(errors) )
        instance.get_valid_credit_card("cctest6", "1234987600000008", False, errors)
        self.assertEquals( 0, len(errors) )
        instance.get_valid_credit_card("cctest7", "12349876000000081", False, errors)
        self.assertEquals( 1, len(errors) )
        instance.get_valid_credit_card("cctest8", "4417 1234 5678 9112", False, errors)
        self.assertEquals( 2, len(errors) )
    
    def test_is_valid_date(self):
        instance = ESAPI.validator()
        format = "%B %d, %Y"
        self.assertTrue(instance.is_valid_date("datetest1", "September 11, 2001", format, True ) )
        self.assertFalse( instance.is_valid_date("datetest2", None, format, False ) )
        self.assertFalse( instance.is_valid_date("datetest3", "", format, False ) )
    
    def test_get_valid_date(self):
        instance = ESAPI.validator()
        errors = ValidationErrorList()
        
        self.assertTrue(instance.get_valid_date("datetest1", "June 23, 1967", "%B %d, %Y", False ))
        instance.get_valid_date("datetest2", "freakshow", "%B %d, %Y", False, errors )
        self.assertEquals( 1, len(errors) )
        
        instance.get_valid_date( "test", "June 32, 2008", "%B %d, %Y", False, errors )
        self.assertEquals( 2, len(errors) )
        
    def test_is_valid_number(self):
        instance = ESAPI.validator();
    
        # Integer
    
        # testing negative range
        self.assertFalse(instance.is_valid_number("test", int, "-4", 1, 10, False));
        self.assertTrue(instance.is_valid_number("test", int, "-4", -10, 10, False));
        # testing null value
        self.assertTrue(instance.is_valid_number("test", int, None, -10, 10, True));
        self.assertFalse(instance.is_valid_number("test", int, None, -10, 10, False));
        # testing empty string
        self.assertTrue(instance.is_valid_number("test", int, "", -10, 10, True));
        self.assertFalse(instance.is_valid_number("test", int, "", -10, 10, False));
        # testing improper range
        self.assertFalse(instance.is_valid_number("test", int, "5", 10, -10, False));
        # testing non-integers
        self.assertFalse(instance.is_valid_number("test", int, "4.3214", -10, 10, True));
        self.assertFalse(instance.is_valid_number("test", int, "-1.65", -10, 10, True));
        # other testing
        self.assertTrue(instance.is_valid_number("test", int, "4", 1, 10, False));
        self.assertTrue(instance.is_valid_number("test", int, "400", 1, 10000, False));
        self.assertTrue(instance.is_valid_number("test", int, "400000000", 1, 400000000, False));
        self.assertFalse(instance.is_valid_number("test", int, "4000000000000", 1, 10000, False));
        self.assertFalse(instance.is_valid_number("test", int, "alsdkf", 10, 10000, False));
        self.assertFalse(instance.is_valid_number("test", int, "--10", 10, 10000, False));
        self.assertFalse(instance.is_valid_number("test", int, "14.1414234x", 10, 10000, False));
        self.assertFalse(instance.is_valid_number("test", int, "Infinity", 10, 10000, False));
        self.assertFalse(instance.is_valid_number("test", int, "-Infinity", 10, 10000, False));
        self.assertFalse(instance.is_valid_number("test", int, "NaN", 10, 10000, False));
        self.assertFalse(instance.is_valid_number("test", int, "-NaN", 10, 10000, False));
        self.assertFalse(instance.is_valid_number("test", int, "+NaN", 10, 10000, False));
        self.assertFalse(instance.is_valid_number("test", int, "1e-6", -999999999, 999999999, False));
        self.assertFalse(instance.is_valid_number("test", int, "-1e-6", -999999999, 999999999, False));
        
        # Floats
        
        # testing negative range
        self.assertFalse(instance.is_valid_number("test", float, "-4", 1, 10, False));
        self.assertTrue(instance.is_valid_number("test", float, "-4", -10, 10, False));
        # testing null value
        self.assertTrue(instance.is_valid_number("test", float, None, -10, 10, True));
        self.assertFalse(instance.is_valid_number("test", float, None, -10, 10, False));
        # testing empty string
        self.assertTrue(instance.is_valid_number("test", float, "", -10, 10, True));
        self.assertFalse(instance.is_valid_number("test", float, "", -10, 10, False));
        # testing improper range
        self.assertFalse(instance.is_valid_number("test", float, "5", 10, -10, False));
        # testing non-integers
        self.assertTrue(instance.is_valid_number("test", float, "4.3214", -10, 10, True));
        self.assertTrue(instance.is_valid_number("test", float, "-1.65", -10, 10, True));
        # other testing
        self.assertTrue(instance.is_valid_number("test", float, "4", 1, 10, False));
        self.assertTrue(instance.is_valid_number("test", float, "400", 1, 10000, False));
        self.assertTrue(instance.is_valid_number("test", float, "400000000", 1, 400000000, False));
        self.assertFalse(instance.is_valid_number("test", float, "4000000000000", 1, 10000, False));
        self.assertFalse(instance.is_valid_number("test", float, "alsdkf", 10, 10000, False));
        self.assertFalse(instance.is_valid_number("test", float, "--10", 10, 10000, False));
        self.assertFalse(instance.is_valid_number("test", float, "14.1414234x", 10, 10000, False));
        self.assertFalse(instance.is_valid_number("test", float, "Infinity", 10, 10000, False));
        self.assertFalse(instance.is_valid_number("test", float, "-Infinity", 10, 10000, False));
        self.assertFalse(instance.is_valid_number("test", float, "NaN", 10, 10000, False));
        self.assertFalse(instance.is_valid_number("test", float, "-NaN", 10, 10000, False));
        self.assertFalse(instance.is_valid_number("test", float, "+NaN", 10, 10000, False));
        self.assertTrue(instance.is_valid_number("test", float, "1e-6", -999999999, 999999999, False));
        self.assertTrue(instance.is_valid_number("test", float, "-1e-6", -999999999, 999999999, False));
    
    def test_get_valid_number(self):
        instance = ESAPI.validator()
        errors = ValidationErrorList();
        
        # Floats
        instance.get_valid_number("dtest1", float, "1.0", 0, 20, True, errors );
        self.assertEquals( 0, len(errors) );
        instance.get_valid_number("dtest2", float, None, 0, 20, True, errors );
        self.assertEquals( 0, len(errors) );
        instance.get_valid_number("dtest3", float, None, 0, 20, False, errors );
        self.assertEquals( 1, len(errors) );
        instance.get_valid_number("dtest4", float, "ridiculous", 0, 20, True, errors );
        self.assertEquals( 2, len(errors) );
        instance.get_valid_number("dtest5", float, "99999999.9", 0, 20, True, errors );
        self.assertEquals( 3, len(errors) );
    
    def test_is_valid_dir_path(self):
        encoder_class = ESAPI.security_configuration().get_class_for_interface('encoder')
        validator_class = ESAPI.security_configuration().get_class_for_interface('validator')
        encoder = encoder_class([HTMLEntityCodec()])
        instance = validator_class(encoder)
        
        if os.name == 'nt': # Windows
            # Windows paths that don't exist and thus should fail
            self.assertFalse(instance.is_valid_directory_path("test", "c:\\ridiculous", "c:\\", False))
            self.assertFalse(instance.is_valid_directory_path("test", "c:\\jeff", "c:\\", False))
            self.assertFalse(instance.is_valid_directory_path("test", "c:\\temp\\..\\etc", "c:\\", False))
            
            # When the parent directory doesn't exist, these should fail
            self.assertFalse(instance.is_valid_directory_path("test", "c:\\", "c:\\ridiculous", False))
            self.assertFalse(instance.is_valid_directory_path("test", "c:\\", None, False))
            
            # Windows paths that should pass
            self.assertTrue(instance.is_valid_directory_path("test", "C:\\", "C:\\", False)) # Windows root directory
            self.assertTrue(instance.is_valid_directory_path("test", "C:\\Windows", "C:\\", False)) # Windows always exist directory
            
            # Should fail for files
            self.assertFalse(instance.is_valid_directory_path("test", "C:\\Windows\\System32\\cmd.exe", "C:\\", False)) # Windows command shell	
            
            # Testing case insensitivity between input and parent_dir
            self.assertTrue(instance.is_valid_directory_path("test", "C:\\", "c:\\", False)) # Windows root directory
            self.assertTrue(instance.is_valid_directory_path("test", "c:\\Windows", "C:\\", False)) # Windows always exist directory
            
            # Testing the verification of the parent directory
            self.assertFalse(instance.is_valid_directory_path("test", "c:\\", "C:\\windows", False)) # Windows always exist directory
            self.assertFalse(instance.is_valid_directory_path("test", "C:\\", "C:\\windows", False)) # Windows always exist directory
            
            # Unix specific paths should not pass
            self.assertFalse(instance.is_valid_directory_path("test", "/tmp", "/", False))	# Unix Temporary directory
            self.assertFalse(instance.is_valid_directory_path("test", "/bin/sh", "/", False))	# Unix Standard shell	
            self.assertFalse(instance.is_valid_directory_path("test", "/etc/config", "/", False))
            
            # Unix specific paths that should not exist or work
            self.assertFalse(instance.is_valid_directory_path("test", "/etc/ridiculous", "/", False))
            self.assertFalse(instance.is_valid_directory_path("test", "/tmp/../etc", "/", False))
        else:
            # Windows paths should fail
            self.assertFalse(instance.is_valid_directory_path("test", "c:\\ridiculous", "c:\\", False))
            self.assertFalse(instance.is_valid_directory_path("test", "c:\\temp\\..\\etc", "c:\\", False))

            # Standard Windows locations should fail
            self.assertFalse(instance.is_valid_directory_path("test", "c:\\", "c:\\", False))
            self.assertFalse(instance.is_valid_directory_path("test", "c:\\Windows\\temp", "c:\\", False))
            self.assertFalse(instance.is_valid_directory_path("test", "c:\\Windows\\System32\\cmd.exe", "c:\\", False))
            
            # Unix specific paths should pass
            # Root
            self.assertTrue(instance.is_valid_directory_path("test", "/", "/", False))
            # /bin
            self.assertTrue(instance.is_valid_directory_path("test", "/bin", "/", False))
            
            # Unix specific paths that should not exist or work
            self.assertFalse(instance.is_valid_directory_path("test", "/etc/ridiculous", "/", False))
            self.assertFalse(instance.is_valid_directory_path("test", "/tmp/../etc", "/", False))
        
    def test_get_valid_dir_path(self):
        instance = ESAPI.validator()
        errors = ValidationErrorList()
        
        parent = "c:\\" if os.name == 'nt' else "/"
        
        # path of this file
        full_path = os.path.abspath(__file__)
        path, filename = os.path.split(full_path)
       
        instance.get_valid_directory_path("dirtest1", path, parent, True, errors);
        self.assertEquals( 0, len(errors) );
        instance.get_valid_directory_path("dirtest2", None, parent, False, errors);
        self.assertEquals( 1, len(errors) );
        instance.get_valid_directory_path("dirtest3", "ridicul%00ous", parent, False, errors);
        self.assertEquals( 2, len(errors) );
        
    def test_is_valid_filename(self):
        instance = ESAPI.validator()
        
        # .txt extension is allowed by default
        
        # Simple valid filename with a valid extension
        self.assertTrue(instance.is_valid_filename("test", "aspect.txt", False))
        
        # Testing case insensitivity of extensions
        self.assertTrue(instance.is_valid_filename("test", "aspect.TXT", False))
        
        # All valid filename characters are accepted
        self.assertTrue(instance.is_valid_filename("test", "!@#$%^&{}[]()_+-=,.~'` abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.txt", False))
        
        # Input that decodes to legal filenames are accepted
        self.assertTrue(instance.is_valid_filename("test", "aspe%20ct.txt", False))
        
        # Valid filename but not in the allowed extension list
        ext = ['.doc', '.xls', '.jpg']
        self.assertFalse(instance.is_valid_filename("test", "aspect.jar", False, ext))
        
    def test_get_valid_filename(self):
        instance = ESAPI.validator()
        
        # Percent encoding is not changed
        test_name = "aspe%20ct.txt"
        self.assertEquals(test_name, instance.get_valid_filename("test", test_name, False))
    def test_is_valid_input(self):
        instance = ESAPI.validator()
        
        self.assertTrue(instance.is_valid_input("test", "jeff.williams@aspectsecurity.com", "Email", 100, False));
        self.assertFalse(instance.is_valid_input("test", "jeff.williams@@aspectsecurity.com", "Email", 100, False));
        self.assertFalse(instance.is_valid_input("test", "jeff.williams@aspectsecurity", "Email", 100, False));
        self.assertTrue(instance.is_valid_input("test", "123.168.100.234", "IPAddress", 100, False));
        self.assertTrue(instance.is_valid_input("test", "192.168.1.234", "IPAddress", 100, False));
        self.assertFalse(instance.is_valid_input("test", "..168.1.234", "IPAddress", 100, False));
        self.assertFalse(instance.is_valid_input("test", "10.x.1.234", "IPAddress", 100, False));
        self.assertTrue(instance.is_valid_input("test", "http://www.aspectsecurity.com", "URL", 100, False));
        self.assertFalse(instance.is_valid_input("test", "http:///www.aspectsecurity.com", "URL", 100, False));
        self.assertFalse(instance.is_valid_input("test", "http://www.aspect security.com", "URL", 100, False));
        self.assertTrue(instance.is_valid_input("test", "078-05-1120", "SSN", 100, False));
        self.assertTrue(instance.is_valid_input("test", "078 05 1120", "SSN", 100, False));
        self.assertTrue(instance.is_valid_input("test", "078051120", "SSN", 100, False));
        self.assertFalse(instance.is_valid_input("test", "987-65-4320", "SSN", 100, False));
        self.assertFalse(instance.is_valid_input("test", "000-00-0000", "SSN", 100, False));
        self.assertFalse(instance.is_valid_input("test", "(555) 555-5555", "SSN", 100, False));
        self.assertFalse(instance.is_valid_input("test", "test", "SSN", 100, False));

        self.assertTrue(instance.is_valid_input("test", None, "Email", 100, True));
        self.assertFalse(instance.is_valid_input("test", None, "Email", 100, False));
        
    def test_get_valid_input(self):
        pass

    def test_is_valid_number(self):
        instance = ESAPI.validator()
        
        # testing negative range
        self.assertFalse(instance.is_valid_number("test", int, "-4", 1, 10, False))
        self.assertTrue(instance.is_valid_number("test", int, "-4", -10, 10, False))
        # testing null value
        self.assertTrue(instance.is_valid_number("test", int, None, -10, 10, True))
        self.assertFalse(instance.is_valid_number("test", int, None, -10, 10, False))
        # testing empty string
        self.assertTrue(instance.is_valid_number("test", int, "", -10, 10, True))
        self.assertFalse(instance.is_valid_number("test", int, "", -10, 10, False))
        # testing improper range
        self.assertFalse(instance.is_valid_number("test", int, "5", 10, -10, False))
        # testing non-integers
        self.assertTrue(instance.is_valid_number("test", float, "4.3214", -10, 10, True))
        self.assertTrue(instance.is_valid_number("test", float, "-1.65", -10, 10, True))
        # other testing
        self.assertTrue(instance.is_valid_number("test", int, "4", 1, 10, False))
        self.assertTrue(instance.is_valid_number("test", int, "400", 1, 10000, False))
        self.assertTrue(instance.is_valid_number("test", int, "400000000", 1, 400000000, False))
        self.assertFalse(instance.is_valid_number("test", int, "4000000000000", 1, 10000, False))
        self.assertFalse(instance.is_valid_number("test", int, "alsdkf", 10, 10000, False))
        self.assertFalse(instance.is_valid_number("test", int, "--10", 10, 10000, False))
        self.assertFalse(instance.is_valid_number("test", int, "14.1414234x", 10, 10000, False))
        self.assertFalse(instance.is_valid_number("test", int, "Infinity", 10, 10000, False))
        self.assertFalse(instance.is_valid_number("test", int, "-Infinity", 10, 10000, False))
        self.assertFalse(instance.is_valid_number("test", int, "NaN", 10, 10000, False))
        self.assertFalse(instance.is_valid_number("test", int, "-NaN", 10, 10000, False))
        self.assertFalse(instance.is_valid_number("test", int, "+NaN", 10, 10000, False))
                
    def test_get_valid_number(self):
        pass
        
    def test_is_valid_file_content(self):
        instance = ESAPI.validator()
        
        content = "This is some file content"
        self.assertTrue(instance.is_valid_file_content("test", content, 100, False))
        
    def test_get_valid_file_content(self):
        instance = ESAPI.validator()
        errors = ValidationErrorList()
        
        content = "12345"
        instance.get_valid_file_content("test", content, 5, True, errors)
        self.assertEquals(0, len(errors))
        instance.get_valid_file_content("test", content, 4, True, errors)
        self.assertEquals(1, len(errors))
        
    def test_is_valid_file_upload(self):
        directory_path = os.path.expanduser('~')
        if os.name == 'nt': # Windows
            parent = "c:\\"
        else:
            parent = "/"
        filename = "aspect.txt"
        content = "This is some file content"
        instance = ESAPI.validator()
        self.assertTrue(instance.is_valid_file_upload("test", directory_path, parent, filename, content, 100, False))
        
        # Test invalid directory path
        directory_path = "c:\\ridiculous"
        self.assertFalse(instance.is_valid_file_upload("test", directory_path, parent, filename, content, 100, False))
    
    def test_assert_valid_file_upload(self):
        pass
        
    def test_is_valid_http_request(self):
        pass
    
    def test_assert_valid_http_request(self):
        pass
        
    def test_is_valid_http_request_parameter_set(self):
        pass
        
    def test_assert_is_valid_http_request_parameter_set(self):
        pass
        
    def test_is_valid_redirect_location(self):
        pass
        
    def test_get_valid_redirect_location(self):
        pass
        
    def test_safe_read_line(self):
        pass
                
if __name__ == "__main__":
    unittest.main()

