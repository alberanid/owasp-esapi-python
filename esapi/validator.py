#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: The Validator interface defines a set of methods for canonicalizing 
    and validating untrusted input.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

class Validator():
    """
    The Validator interface defines a set of methods for canonicalizing and
    validating untrusted input. Implementors should feel free to extend this
    interface to accommodate their own data formats. Methods prefixed with "is"
    should return boolean values. Methods with a "get" prefix should return
    valid input or raise an exception.
    
    For "get" methods, invalid input should generate a descriptive 
    ValidationException, and input that is clearly an attack should generate a
    descriptive IntrusionException.
    
    "assert" and "get" methods should accept an optional error_list parameter 
    to collect any thrown errors instead of raising them. This error_list 
    parameter can accept an instance of the ValidationErrorList class. If the
    errors_list is present, any exceptions are added to the list instead of 
    being thrown, and the method returns None.
    
    
    Implementations must adopt a "whitelist" approach to validation where a
    specific pattern or character set is matched. "Blacklist" approaches that
    attempt to identify the invalid or disallowed characters are much more likely
    to be fooled by encoding or other tricks.

    @author: Craig Younkins (craig.younkins@owasp.org)
    """
    
    def __init__(self):
        pass

    def is_valid_input(self, context,
                           input_,
                           type_,
                           max_length,
                           allow_none):
        """
        Returns true if input is valid according to the specified type. The 
        type parameter must be the name of a defined type in the ESAPI 
        configuration or a valid regular expression. Implementers should take
        care to make the type storage simple to understand and configure.

        @param context: A descriptive name of the parameter that you are validating 
            (e.g., LoginPage_UsernameField). This value is used by any 
            logging or error handling that is done with respect to the 
            value passed in.
        @param input_: The actual user input data to validate.
        @param type_: The regular expression name that maps to the actual regular 
            expression from "ESAPI.conf.settings".
        @param max_length: The maximum post-canonicalized String length allowed.
        @param allow_none: If allow_none is true then an input that is NONE or an empty 
            string will be legal. If allow_none is false then NONE or an 
            empty String will throw a ValidationException.

        @return: true, if the input is valid based on the rules set by 'type'
            otherwise, false.

        @raises IntrusionException: 
        """
        raise NotImplementedError()

    def get_valid_input(self, context,
                              input_,
                              type_,
                              max_length,
                              allow_none,
                              error_list=None):
        """
        Returns canonicalized and validated input as a String.

        @param context: A descriptive name of the parameter that you are validating 
            (e.g., LoginPage_UsernameField). This value is used by any 
            logging or error handling that is done with respect to the 
            value passed in.
        @param input_: The actual user input data to validate.
        @param type_: The regular expression name that maps to the actual regular 
            expression from "ESAPI.conf.settings".
        @param max_length: The maximum post-canonicalized String length allowed.
        @param allow_none: If allow_none is true then an input that is NONE or an empty 
            string will be legal. If allow_none is false then NONE or an 
            empty String will throw a ValidationException.
        @param error_list: If error_list exists, any errors will be captured in the list
            instead of being thrown. The method will return None in this
            case.

        @return: The canonicalized user input.

        @raise IntrusionException:
        """
        raise NotImplementedError()

    def is_valid_date(self, context, input_, format_, allow_none):
        """
        Returns true if input is a valid date according to the specified date
        format.

        @param context: A descriptive name of the parameter that you are validating 
            (e.g., LoginPage_UsernameField). This value is used by any 
            logging or error handling that is done with respect to the 
            value passed in.
        @param input_: The actual user input data to validate.
        @param format_: Required formatting of date in string form, according to
            Python's U{datetime.strptime<http://docs.python.org/library/datetime.html>}.
        @param allow_none: If allow_none is true then an input that is NONE or an empty 
            string will be legal. If allow_none is false then NONE or an 
            empty String will throw a ValidationException.

        @return: true, if input is a valid date according to the format 
            specified by 'format'. Otherwise, false.
        """
        raise NotImplementedError()

    def get_valid_date(self, context,
                             input_,
                             format_,
                             allow_none,
                             error_list=None):
        """
        Returns a valid date as a U{datetime<http://docs.python.org/library/datetime.html#datetime-objects>} object. 

        @param context: A descriptive name of the parameter that you are validating 
            (e.g., LoginPage_UsernameField). This value is used by any 
            logging or error handling that is done with respect to the 
            value passed in.
        @param input_: The actual user input data to validate.
        @param format_: Required formatting of date inputted.
        @param allow_none: If allow_none is true then an input that is NONE or an empty 
            string will be legal. If allow_none is false then NONE or an 
            empty String will throw a ValidationException.
        @param error_list: If error_list exists, any errors will be captured in the list
            instead of being thrown. The method will return None in this
            case.
        @return: A valid date as a Date

        @raise IntrusionException:
        """
        raise NotImplementedError()

    def is_valid_safe_html(self, context, input_, max_length, allow_none):
        """
        Returns true if input is "safe" HTML. Implementors should reference the
        OWASP AntiSamy project for ideas on how to do HTML validation in a 
        whitelist way, as this is an extremely difficult problem.

        @param context: A descriptive name of the parameter that you are validating 
            (e.g., LoginPage_UsernameField). This value is used by any 
            logging or error handling that is done with respect to the 
            value passed in.
        @param input_: The actual user input data to validate.
        @param max_length: The maximum post-canonicalized String length allowed.
        @param allow_none: If allow_none is true then an input that is NONE or an empty 
            string will be legal. If allow_none is false then NONE or an 
            empty String will throw a ValidationException.

        @return: true, if input is valid safe HTML. Otherwise false.

        @raises IntrusionException:
        """
        raise NotImplementedError()

    def get_valid_safe_html(self, context,
                                 input_,
                                 max_length,
                                 allow_none,
                                 error_list=None):
        """
        Returns canonicalized and validated "safe" HTML. Implementors should 
        reference the OWASP AntiSamy project for ideas on how to do HTML 
        validation in a whitelist way, as this is an extremely difficult 
        problem.

        @param context: A descriptive name of the parameter that you are validating 
            (e.g., LoginPage_UsernameField). This value is used by any 
            logging or error handling that is done with respect to the 
            value passed in.
        @param input_: The actual user input data to validate.
        @param max_length: The maximum post-canonicalized String length allowed.
        @param allow_none: If allow_none is true then an input that is NONE or an empty 
            string will be legal. If allow_none is false then NONE or an 
            empty String will throw a ValidationException.
        @param error_list: If error_list exists, any errors will be captured in the list
            instead of being thrown. The method will return None in this
            case.
        @return: Valid safe HTML

        @raise IntrusionException:
        """
        raise NotImplementedError()

    def is_valid_credit_card(self, context, input_, allow_none):
        """
        Returns true if input is a valid credit card. Implementors should
        use the Luhn algorithm at the very least.

        @param context: A descriptive name of the parameter that you are validating 
            (e.g., LoginPage_UsernameField). This value is used by any 
            logging or error handling that is done with respect to the 
            value passed in.
        @param input_: The actual user input data to validate.
        @param allow_none: If allow_none is true then an input that is NONE or an empty 
            string will be legal. If allow_none is false then NONE or an 
            empty String will throw a ValidationException.

        @return: true, if input is a valid credit card number. Otherwise, false.

        @raise IntrusionException:
        """
        raise NotImplementedError()

    def get_valid_credit_card(self, context, input_, allow_none, error_list=None):
        """
        Returns a canonicalized and validated credit card number as a String, 
        including only the digits (no spaces).

        @param context: A descriptive name of the parameter that you are validating 
            (e.g., LoginPage_UsernameField). This value is used by any 
            logging or error handling that is done with respect to the 
            value passed in.
        @param input_: The actual input data to validate.
        @param allow_none: If allow_none is true then an input that is NONE or an empty 
            string will be legal. If allow_none is false then NONE or an 
            empty String will throw a ValidationException.
        @param error_list: If error_list exists, any errors will be captured in the list
            instead of being thrown. The method will return None in this
            case.
                
        @return: A valid credit card number

        @raise IntrusionException:
        """
        raise NotImplementedError()

    def is_valid_directory_path(self, context, input_, parent_dir, allow_none):
        """
        Returns true if input is a valid directory path.
        
        To be a valid directory, the input_ must
            - Exist on disk
            - Be a directory
            - Be a subdirectory of the parent_dir parameter, a full path to a 
              parent directory, which must also exist and be a directory

        @param context: A descriptive name of the parameter that you are validating 
            (e.g., LoginPage_UsernameField). This value is used by any 
            logging or error handling that is done with respect to the 
            value passed in.
        @param input_: The actual input data to validate.
        @param parent_dir: A parent directory that the input_ must be under. Use this to
            ensure any uploads go into allowed directories.
        @param allow_none: If allow_none is true then an input that is NONE or an empty 
            string will be legal. If allow_none is false then NONE or an 
            empty String will throw a ValidationException.

        @return: true, if input is a valid directory path. Otherwise, false.

        @raise IntrusionException:
        """
        raise NotImplementedError()

    def get_valid_directory_path(self, context, input_, parent_dir, allow_none, error_list=None):
        """
        Returns a canonicalized and validated directory path as a String.
        
        To be a valid directory, the input_ must
            - Exist on disk
            - Be a directory
            - Be a subdirectory of the parent_dir parameter, a full path to a 
              parent directory, which must also exist and be a directory

        @param context: A descriptive name of the parameter that you are validating 
            (e.g., LoginPage_UsernameField). This value is used by any 
            logging or error handling that is done with respect to the 
            value passed in.
        @param input_: The actual input data to validate.
        @param parent_dir: A parent directory that the input_ must be under. Use this to
            ensure any uploads go into allowed directories.
        @param allow_none: If allow_none is true then an input that is NONE or an empty 
            string will be legal. If allow_none is false then NONE or an 
            empty String will throw a ValidationException.
        @param error_list: If error_list exists, any errors will be captured in the list
            instead of being thrown. The method will return None in this
            case.

        @return: A valid directory path

        @raise IntrusionException:
        """
        raise NotImplementedError()

    def is_valid_filename(self, context, input_, allow_none, allowed_extensions=None):
        """
        Returns true if input is a valid file name.
        
        To be a valid filename, the input_ must
            - Be well formed
            - Have an extension in allowed_extensions, or, if that list is None, in
              the list defined by 
              ESAPI.security_configuration().get_allowed_file_extensions()

        @param context: A descriptive name of the parameter that you are validating 
            (e.g., LoginPage_UsernameField). This value is used by any 
            logging or error handling that is done with respect to the 
            value passed in.
        @param input_: The actual input data to validate.
        @param allow_none: If allow_none is true then an input that is NONE or an empty 
            string will be legal. If allow_none is false then NONE or an 
            empty String will throw a ValidationException.

        @return: true, if input is a valid file name. Otherwise, false.

        @raise IntrusionException:
        """
        raise NotImplementedError()

    def get_valid_filename(self, context, input_, allow_none, error_list=None, allowed_extensions=None):
        """
        Returns a canonicalized and validated file name as a String. 

        To be a valid filename, the input_ must
            - Be well formed
            - Have an extension in allowed_extensions, or, if that list is None, in
              the list defined by 
              ESAPI.security_configuration().get_allowed_file_extensions()
        
        @param context: A descriptive name of the parameter that you are validating 
            (e.g., LoginPage_UsernameField). This value is used by any 
            logging or error handling that is done with respect to the 
            value passed in.
        @param input_: The actual input data to validate.
        @param allow_none: If allow_none is true then an input that is NONE or an empty 
            string will be legal. If allow_none is false then NONE or an 
            empty String will throw a ValidationException.
        @param error_list: If error_list exists, any errors will be captured in the list
            instead of being thrown. The method will return None in this
            case.
            
        @return: A valid file name

        @raise IntrusionException:
        """
        raise NotImplementedError()

    def is_valid_number(self, context, num_type, input_, min_value, max_value, allow_none):
        """
        Returns true if input is a valid number within the range of min_value
        to max_value. num_type is an important parameter - it sets the type the
        number should be. This could be int or float, and so this method works
        for these types and more.

        @param context: A descriptive name of the parameter that you are validating 
            (e.g., LoginPage_UsernameField). This value is used by any 
            logging or error handling that is done with respect to the 
            value passed in.
        @param input_: The actual input data to validate.
        @param min_value: Lowest legal value for input.
        @param max_value: Highest legal value for input.
        @param allow_none: If allow_none is true then an input that is NONE or an empty 
            string will be legal. If allow_none is false then NONE or an 
            empty String will throw a ValidationException.

        @return: true, if input is a valid number. Otherwise, false.

        @raise IntrusionException:
        """
        raise NotImplementedError()

    def get_valid_number(self, context, 
                               num_type,
                               input_,
                               min_value,
                               max_value,
                               allow_none,
                               error_list=None):
        """
        Returns a validated number that is within the range of min_value
        to max_value. num_type is an important parameter - it sets the type the
        number should be. This could be int or float, and so this method works
        for these types and more.

        @param context: A descriptive name of the parameter that you are validating 
            (e.g., LoginPage_UsernameField). This value is used by any 
            logging or error handling that is done with respect to the 
            value passed in.
        @param input_: The actual input data to validate.
        @param min_value: Lowest legal value for input.
        @param max_value: Highest legal value for input.
        @param allow_none: If allow_none is true then an input that is NONE or an empty 
            string will be legal. If allow_none is false then NONE or an 
            empty String will throw a ValidationException.
        @param error_list: If error_list exists, any errors will be captured in the list
            instead of being thrown. The method will return None in this
            case.
            
        @return: A validated number as a double.

        @raise IntrusionException:
        """
        raise NotImplementedError()

    def is_valid_file_content(self, context, input_, max_bytes, allow_none):
        """
        Returns true if input is valid file content. This is a good place to 
        check for max file size, allowed character sets, and do virus scans.

        @param context: A descriptive name of the parameter that you are validating 
            e.g., LoginPage_UsernameField). This value is used by any 
            logging or error handling that is done with respect to the 
            value passed in.
        @param input_: The actual input data to validate.
        @param max_bytes: The maximum number of bytes allowed in a legal file.
        @param allow_none: If allow_none is true then an input that is NONE or an empty 
            string will be legal. If allow_none is false then NONE or an 
            empty String will throw a ValidationException.

        @return: true, if input contains valid file content. Otherwise, false.

        @raise IntrusionException:
        """
        raise NotImplementedError()

    def get_valid_file_content(self, context,
                                    input_,
                                    max_bytes,
                                    allow_none,
                                    error_list=None):
        """
        Returns validated file content as a string. This is a good place to 
        check for max file size, allowed character sets, and do virus scans.  

        @param context: A descriptive name of the parameter that you are validating 
            (e.g., LoginPage_UsernameField). This value is used by any 
            logging or error handling that is done with respect to the 
            value passed in.
        @param input_: The actual input data to validate.
        @param max_bytes: The maximum number of bytes allowed in a legal file.
        @param allow_none: If allow_none is true then an input that is NONE or an empty 
            string will be legal. If allow_none is false then NONE or an 
            empty String will throw a ValidationException.
        @param error_list: If error_list exists, any errors will be captured in the list
            instead of being thrown. The method will return None in this
            case.
            
        @return: A string containing valid file content.

        @raise IntrusionException:
        """
        raise NotImplementedError()

    def is_valid_file_upload(self, context,
                                directory_path,
                                parent,
                                filename,
                                content,
                                max_bytes,
                                allow_none):
        """
        Returns true if the the directory, filename, and content of a file 
        upload are all valid.

        @param context: A descriptive name of the parameter that you are validating 
            (e.g., LoginPage_UsernameField). This value is used by any 
            logging or error handling that is done with respect to the 
            value passed in.
        @param directory_path: The directory path of the uploaded file.
        @param parent: The parent directory that all uploads must be inside.
        @param filename: The filename of the uploaded file
        @param content: A byte array containing the content of the uploaded file.
        @param max_bytes: The max number of bytes allowed for a legal file upload.
        @param allow_none: If allow_none is true then an input that is NONE or an empty 
            string will be legal. If allow_none is false then NONE or an 
            empty String will throw a ValidationException.

        @return: true, if a file upload has a valid name, path, and content.

        @raise IntrusionException:
        """
        raise NotImplementedError()

    def assert_valid_file_upload(self, context,
                                      directory_path,
                                      parent,
                                      filename,
                                      content,
                                      max_bytes,
                                      allow_none,
                                      error_list=None):
        """
        Validates the directory, filename, and content of a file upload.

        @param context: A descriptive name of the parameter that you are validating 
            (e.g., LoginPage_UsernameField). This value is used by any 
            logging or error handling that is done with respect to the 
            value passed in.
        @param directory_path: The directory path of the uploaded file.
        @param parent: The parent directory that all uploads must be inside.
        @param filename: The filename of the uploaded file
        @param content: A byte array containing the content of the uploaded file.
        @param max_bytes: The max number of bytes allowed for a legal file upload.
        @param allow_none: If allow_none is true then an input that is NONE or an empty 
            string will be legal. If allow_none is false then NONE or an 
            empty String will throw a ValidationException.
        @param error_list: If error_list exists, any errors will be captured in the list
            instead of being thrown. The method will return None in this
            case.

        @raise IntrusionException:
        """
        raise NotImplementedError()

    def is_valid_http_request(self, request):
        """
        Validate the current HTTP request by comparing parameters, headers, and 
        cookies to a predefined whitelist of allowed characters. See the 
        SecurityConfiguration class for the methods to retrieve the whitelists.

        @return: true, if is a valid HTTP request

        @raises IntrusionException: 
        """
        raise NotImplementedError()

    def assert_is_valid_http_request(self, request):
        """
        Validates the current HTTP request by comparing parameters, headers, 
        and cookies to a predefined whitelist of allowed characters.

        @raises ValidationException: @raises IntrusionException
        """
        raise NotImplementedError()

    def is_valid_http_request_parameter_set(self, context, required, optional):
        """
        Returns true if the parameters in the current request contain all 
        required parameters and only optional ones in addition.

        @param context: A descriptive name of the parameter that you are 
            validating (e.g., LoginPage_UsernameField). This value is used by any 
            logging or error handling that is done with respect to the value passed 
            in.
        @param required: parameters that are required to be in HTTP request
        @param optional: additional parameters that may be in HTTP request

        @return: true, if all required parameters are in HTTP request and only 
            optional parameters in addition.  Returns false if parameters are 
            found in HTTP request that are not in either set (required or 
            optional), or if any required parameters are missing from request.

        @raises IntrusionException: 
        """
        raise NotImplementedError()

    def assert_is_valid_http_request_parameter_set(self, 
                                                   context, 
                                                   required, 
                                                   optional, 
                                                   error_list=None):
        """
        Validates that the parameters in the current request contain all 
        required parameters and only optional ones in addition. 

        @param context: A descriptive name of the parameter that you are 
            validating (e.g., LoginPage_UsernameField). This value is used by any 
            logging or error handling that is done with respect to the value 
            passed in.
        @param required: parameters that are required to be in HTTP request
        @param optional: additional parameters that may be in HTTP request
        @param error_list: If validation is in error, resulting error will be stored in the error_list by context

        @raises IntrusionException: 
        """
        raise NotImplementedError()

    def is_valid_redirect_location(self, context, input_, allow_none):
        """
        Returns true if input is a valid redirect location, as defined by "ESAPI.conf.settings".

        @param context: A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
        @param input_: redirect location to be checked for validity, according to rules set in "ESAPI.conf.settings"
        @param allow_none: If allow_none is true then an input that is NONE or an empty string will be legal. If allow_none is false then NONE or an empty String will throw a ValidationException.

        @return: true, if 'input' is a valid redirect location, as defined by "ESAPI.conf.settings", false otherwise.

        @raises IntrusionException: 
        """
        raise NotImplementedError()

    def get_valid_redirect_location(self, context, input_, allow_none, error_list=None):
        """
        Returns a canonicalized and validated redirect location as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
        will generate a descriptive IntrusionException. Instead of throwing a ValidationException
        on error, this variant will store the exception inside of the ValidationErrorList.

        @param context: A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
        @param input_: redirect location to be returned as valid, according to encoding rules set in "ESAPI.conf.settings"
        @param allow_none: If allow_none is true then an input that is NONE or an empty string will be legal. If allow_none is false then NONE or an empty String will throw a ValidationException.
        @param error_list: If validation is in error, resulting error will be stored in the error_list by context

        @return: A canonicalized and validated redirect location, as defined in "ESAPI.conf.settings"

        @raises IntrusionException: 
        """
        raise NotImplementedError()

    def safe_read_line(self, input_stream, max_length):
        """
        Reads from an input stream until end-of-line or a maximum number of
        characters. This method protects against the inherent denial of service
        attack in reading until the end of a line. If an attacker doesn't ever
        send a newline character, then a normal input stream reader will read
        until all memory is exhausted and the platform raises an OutOfMemoryError
        and probably terminates.

        @param input_stream: The InputStream from which to read data
        @param max_length: Maximum characters allowed to be read in per line

        @return: a String containing the current line of inputStream

        @raises ValidationException: 
        """
        raise NotImplementedError()


