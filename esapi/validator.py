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

class Validator():
    """
    The Validator interface defines a set of methods for canonicalizing and
    validating untrusted input. Implementors should feel free to extend this
    interface to accommodate their own data formats. Rather than throw exceptions,
    this interface returns boolean results because not all validation problems
    are security issues. Boolean returns allow developers to handle both valid
    and invalid results more cleanly than exceptions.
    <P>
    <img src="doc-files/Validator.jpg">
    <P>
    Implementations must adopt a "whitelist" approach to validation where a
    specific pattern or character set is matched. "Blacklist" approaches that
    attempt to identify the invalid or disallowed characters are much more likely
    to allow a bypass with encoding or other tricks.

    @author Craig Younkins (craig.younkins@owasp.org)
    """

    def add_rule(self, rule):
        raise NotImplementedError()

    def get_rule(self, name):
        raise NotImplementedError()

    def is_valid_input(self, context,
                           input_,
                           type_,
                           max_length,
                           allow_none):
        """
        Returns true if input is valid according to the specified type. The type parameter must be the name
        of a defined type in the ESAPI configuration or a valid regular expression. Implementers should take
        care to make the type storage simple to understand and configure.

        @param context
                A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
        @param input_
                The actual user input data to validate.
        @param type_
                The regular expression name that maps to the actual regular expression from "ESAPI.conf.settings".
        @param max_length
                The maximum post-canonicalized String length allowed.
        @param allow_none
                If allow_none is true then an input that is NONE or an empty string will be legal. If allow_none is false then NONE or an empty String will throw a ValidationException.

        @return true, if the input is valid based on the rules set by 'type'

        @throws IntrusionException
        """
        raise NotImplementedError()

    def get_valid_input(self, context,
                              input_,
                              type_,
                              max_length,
                              allow_none,
                              error_list=None):
        """
        Returns canonicalized and validated input as a String. Invalid input will generate a descriptive ValidationException,
        and input that is clearly an attack will generate a descriptive IntrusionException.  Instead of
        throwing a ValidationException on error, this variant will store the exception inside of the ValidationErrorList.

        @param context
                A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
        @param input_
                The actual user input data to validate.
        @param type_
                The regular expression name that maps to the actual regular expression from "ESAPI.conf.settings".
        @param max_length
                The maximum post-canonicalized String length allowed.
        @param allow_none
                If allow_none is true then an input that is NONE or an empty string will be legal. If allow_none is false then NONE or an empty String will throw a ValidationException.
        @param error_list
                If validation is in error, resulting error will be stored in the error_list by context

        @return The canonicalized user input.

        @throws IntrusionException
        """
        raise NotImplementedError()

    def is_valid_date(self, context, input_, format_, allow_none):
        """
        Returns true if input is a valid date according to the specified date format.

        @param context
                A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
        @param input_
                The actual user input data to validate.
        @param format_
                Required formatting of date inputted.
        @param allow_none
                If allow_none is true then an input that is NONE or an empty string will be legal. If allow_none is false then NONE or an empty String will throw a ValidationException.

        @return true, if input is a valid date according to the format specified by 'format'

        @throws IntrusionException
        """
        raise NotImplementedError()

    def get_valid_date(self, context,
                             input_,
                             format_,
                             allow_none,
                             error_list=None):
        """
        Returns a valid date as a Date. Invalid input will generate a descriptive ValidationException and store it inside of
        the error_list argument, and input that is clearly an attack will generate a descriptive IntrusionException.  Instead of
        throwing a ValidationException on error, this variant will store the exception inside of the ValidationErrorList.

        @param context
                A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
        @param input_
                The actual user input data to validate.
        @param format_
                Required formatting of date inputted.
        @param allow_none
                If allow_none is true then an input that is NONE or an empty string will be legal. If allow_none is false then NONE or an empty String will throw a ValidationException.
        @param error_list
                If validation is in error, resulting error will be stored in the error_list by context

        @return A valid date as a Date

        @throws IntrusionException
        """
        raise NotImplementedError()

    def is_valid_safe_html(self, context, input_, max_length, allow_none):
        """
        Returns true if input is "safe" HTML. Implementors should reference the OWASP AntiSamy project for ideas
        on how to do HTML validation in a whitelist way, as this is an extremely difficult problem.

        @param context
                A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
        @param input_
                The actual user input data to validate.
        @param max_length
                The maximum post-canonicalized String length allowed.
        @param allow_none
                If allow_none is true then an input that is NONE or an empty string will be legal. If allow_none is false then NONE or an empty String will throw a ValidationException.

        @return true, if input is valid safe HTML

        @throws IntrusionException
        """
        raise NotImplementedError()

    def get_valid_safe_html(self, context,
                                 input_,
                                 max_length,
                                 allow_none,
                                 error_list=None):
        """
        Returns canonicalized and validated "safe" HTML. Implementors should reference the OWASP AntiSamy project for ideas
        on how to do HTML validation in a whitelist way, as this is an extremely difficult problem. Instead of
        throwing a ValidationException on error, this variant will store the exception inside of the ValidationErrorList.

        @param context
                A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
        @param input_
                The actual user input data to validate.
        @param max_length
                The maximum post-canonicalized String length allowed.
        @param allow_none
                If allow_none is true then an input that is NONE or an empty string will be legal. If allow_none is false then NONE or an empty String will throw a ValidationException.
        @param error_list
                If validation is in error, resulting error will be stored in the error_list by context

        @return Valid safe HTML

        @throws IntrusionException
        """
        raise NotImplementedError()

    def is_valid_credit_card(self, context, input_, allow_none):
        """
        Returns true if input is a valid credit card. Maxlength is mandated by valid credit card type.

        @param context
                A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
        @param input_
                The actual user input data to validate.
        @param allow_none
                If allow_none is true then an input that is NONE or an empty string will be legal. If allow_none is false then NONE or an empty String will throw a ValidationException.

        @return true, if input is a valid credit card number

        @throws IntrusionException
        """
        raise NotImplementedError()

    def get_valid_credit_card(self, context, input_, allow_none, error_list=None):
        """
        Returns a canonicalized and validated credit card number as a String. Invalid input
        will generate a descriptive ValidationException, and input that is clearly an attack
        will generate a descriptive IntrusionException. Instead of throwing a ValidationException
        on error, this variant will store the exception inside of the ValidationErrorList.

        @param context
                A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
        @param input_
                The actual input data to validate.
        @param allow_none
                If allow_none is true then an input that is NONE or an empty string will be legal. If allow_none is false then NONE or an empty String will throw a ValidationException.
        @param error_list
                If validation is in error, resulting error will be stored in the error_list by context

        @return A valid credit card number

        @throws IntrusionException
        """
        raise NotImplementedError()

    def is_valid_directory_path(self, context, input_, allow_none):
        """
        Returns true if input is a valid directory path.

        @param context
                A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
        @param input_
                The actual input data to validate.
        @param allow_none
                If allow_none is true then an input that is NONE or an empty string will be legal. If allow_none is false then NONE or an empty String will throw a ValidationException.

        @return true, if input is a valid directory path

        @throws IntrusionException
        """
        raise NotImplementedError()

    def get_valid_directory_path(self, context, input_, allow_none, error_list=None):
        """
        Returns a canonicalized and validated directory path as a String. Invalid input
        will generate a descriptive ValidationException, and input that is clearly an attack
        will generate a descriptive IntrusionException. Instead of throwing a ValidationException
        on error, this variant will store the exception inside of the ValidationErrorList.

        @param context
                A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
        @param input_
                The actual input data to validate.
        @param allow_none
                If allow_none is true then an input that is NONE or an empty string will be legal. If allow_none is false then NONE or an empty String will throw a ValidationException.
        @param error_list
                If validation is in error, resulting error will be stored in the error_list by context

        @return A valid directory path

        @throws IntrusionException
        """
        raise NotImplementedError()

    def is_valid_filename(self, context, input_, allow_none):
        """
        Returns true if input is a valid file name.

        @param context
                A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
        @param input_
                The actual input data to validate.
        @param allow_none
                If allow_none is true then an input that is NONE or an empty string will be legal. If allow_none is false then NONE or an empty String will throw a ValidationException.

        @return true, if input is a valid file name

        @throws IntrusionException
        """
        raise NotImplementedError()

    def get_valid_filename(self, context, input_, allow_none, error_list=None):
        """
        Returns a canonicalized and validated file name as a String. Implementors should check for allowed file extensions here, as well as allowed file name characters, as declared in "ESAPI.conf.settings".  Invalid input
        will generate a descriptive ValidationException, and input that is clearly an attack
        will generate a descriptive IntrusionException. Instead of throwing a ValidationException
        on error, this variant will store the exception inside of the ValidationErrorList.

        @param context
                A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
        @param input_
                The actual input data to validate.
        @param allow_none
                If allow_none is true then an input that is NONE or an empty string will be legal. If allow_none is false then NONE or an empty String will throw a ValidationException.
        @param error_list
                If validation is in error, resulting error will be stored in the error_list by context

        @return A valid file name

        @throws IntrusionException
        """
        raise NotImplementedError()

    def is_valid_number(self, context,
                            input_,
                            min_value,
                            max_value,
                            allow_none):
        """
        Returns true if input is a valid number within the range of min_value to max_value.

        @param context
                A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
        @param input_
                The actual input data to validate.
        @param min_value
                Lowest legal value for input.
        @param max_value
                Highest legal value for input.
        @param allow_none
                If allow_none is true then an input that is NONE or an empty string will be legal. If allow_none is false then NONE or an empty String will throw a ValidationException.

        @return true, if input is a valid number

        @throws IntrusionException
        """
        raise NotImplementedError()

    def get_valid_number(self, context,
                               input_,
                               min_value,
                               max_value,
                               allow_none,
                               error_list=None):
        """
        Returns a validated number as a double within the range of min_value to max_value. Invalid input
        will generate a descriptive ValidationException, and input that is clearly an attack
        will generate a descriptive IntrusionException. Instead of throwing a ValidationException
        on error, this variant will store the exception inside of the ValidationErrorList.

        @param context
                A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
        @param input_
                The actual input data to validate.
        @param min_value
                Lowest legal value for input.
        @param max_value
                Highest legal value for input.
        @param allow_none
                If allow_none is true then an input that is NONE or an empty string will be legal. If allow_none is false then NONE or an empty String will throw a ValidationException.
        @param error_list
                If validation is in error, resulting error will be stored in the error_list by context

        @return A validated number as a double.

        @throws IntrusionException
        """
        raise NotImplementedError()

    def is_valid_integer(self, context,
                             input_,
                             min_value,
                             max_value,
                             allow_none):
        """
        Returns true if input is a valid integer within the range of min_value to max_value.

        @param context
                A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
        @param input_
                The actual input data to validate.
        @param min_value
                Lowest legal value for input.
        @param max_value
                Highest legal value for input.
        @param allow_none
                If allow_none is true then an input that is NONE or an empty string will be legal. If allow_none is false then NONE or an empty String will throw a ValidationException.

        @return true, if input is a valid integer

        @throws IntrusionException
        """
        raise NotImplementedError()

    def get_valid_integer(self, context,
                                input_,
                                min_value,
                                max_value,
                                allow_none,
                                error_list=None):
        """
        Returns a validated integer. Invalid input
        will generate a descriptive ValidationException, and input that is clearly an attack
        will generate a descriptive IntrusionException. Instead of throwing a ValidationException
        on error, this variant will store the exception inside of the ValidationErrorList.

        @param context
                A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
        @param input_
                The actual input data to validate.
        @param min_value
                Lowest legal value for input.
        @param max_value
                Highest legal value for input.
        @param allow_none
                If allow_none is true then an input that is NONE or an empty string will be legal. If allow_none is false then NONE or an empty String will throw a ValidationException.
        @param error_list
                If validation is in error, resulting error will be stored in the error_list by context

        @return A validated number as an integer.

        @throws IntrusionException
        """
        raise NotImplementedError()

    def is_valid_double(self, context,
                            input_,
                            min_value,
                            max_value,
                            allow_none):
        """
        Returns true if input is a valid double within the range of min_value to max_value.

        @param context
                A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
        @param input_
                The actual input data to validate.
        @param min_value
                Lowest legal value for input.
        @param max_value
                Highest legal value for input.
        @param allow_none
                If allow_none is true then an input that is NONE or an empty string will be legal. If allow_none is false then NONE or an empty String will throw a ValidationException.

        @return true, if input is a valid double.

        @throws IntrusionException

        """
        raise NotImplementedError()

    def get_valid_double(self, context,
                               input_,
                               min_value,
                               max_value,
                               allow_none,
                               error_list=None):
        """
        Returns a validated real number as a double. Invalid input
        will generate a descriptive ValidationException, and input that is clearly an attack
        will generate a descriptive IntrusionException. Instead of throwing a ValidationException
        on error, this variant will store the exception inside of the ValidationErrorList.

        @param context
                A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
        @param input_
                The actual input data to validate.
        @param min_value
                Lowest legal value for input.
        @param max_value
                Highest legal value for input.
        @param allow_none
                If allow_none is true then an input that is NONE or an empty string will be legal. If allow_none is false then NONE or an empty String will throw a ValidationException.
        @param error_list
                If validation is in error, resulting error will be stored in the error_list by context

        @return A validated real number as a double.

        @throws IntrusionException
        """
        raise NotImplementedError()

    def is_valid_file_content(self, context, input_, max_bytes, allow_none):
        """
        Returns true if input is valid file content.  This is a good place to check for max file size, allowed character sets, and do virus scans.

        @param context
                A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
        @param input_
                The actual input data to validate.
        @param max_bytes
                The maximum number of bytes allowed in a legal file.
        @param allow_none
                If allow_none is true then an input that is NONE or an empty string will be legal. If allow_none is false then NONE or an empty String will throw a ValidationException.

        @return true, if input contains valid file content.

        @throws IntrusionException
        """
        raise NotImplementedError()

    def get_valid_file_content(self, context,
                                    input_,
                                    max_bytes,
                                    allow_none,
                                    error_list=None):
        """
        Returns validated file content as a byte array. This is a good place to check for max file size, allowed character sets, and do virus scans.  Invalid input
        will generate a descriptive ValidationException, and input that is clearly an attack
        will generate a descriptive IntrusionException. Instead of throwing a ValidationException
        on error, this variant will store the exception inside of the ValidationErrorList.

        @param context
                A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
        @param input_
                The actual input data to validate.
        @param max_bytes
                The maximum number of bytes allowed in a legal file.
        @param allow_none
                If allow_none is true then an input that is NONE or an empty string will be legal. If allow_none is false then NONE or an empty String will throw a ValidationException.
        @param error_list
                If validation is in error, resulting error will be stored in the error_list by context.

        @return A byte array containing valid file content.

        @throws IntrusionException
        """
        raise NotImplementedError()

    def is_valid_file_upload(self, context,
                                filepath,
                                filename,
                                content,
                                max_bytes,
                                allow_none):
        """
        Returns true if a file upload has a valid name, path, and content.

        @param context
                A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
        @param filepath
                The file path of the uploaded file.
        @param filename
                The filename of the uploaded file
        @param content
                A byte array containing the content of the uploaded file.
        @param max_bytes
                The max number of bytes allowed for a legal file upload.
        @param allow_none
                If allow_none is true then an input that is NONE or an empty string will be legal. If allow_none is false then NONE or an empty String will throw a ValidationException.

        @return true, if a file upload has a valid name, path, and content.

        @throws IntrusionException
        """
        raise NotImplementedError()

    def assert_valid_file_upload(self, context,
                                      filepath,
                                      filename,
                                      content,
                                      max_bytes,
                                      allow_none,
                                      error_list=None):
        """
        Validates the filepath, filename, and content of a file. Invalid input
        will generate a descriptive ValidationException, and input that is clearly an attack
        will generate a descriptive IntrusionException. Instead of throwing a ValidationException
        on error, this variant will store the exception inside of the ValidationErrorList.

        @param context
                A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
        @param filepath
                The file path of the uploaded file.
        @param filename
                The filename of the uploaded file
        @param content
                A byte array containing the content of the uploaded file.
        @param max_bytes
                The max number of bytes allowed for a legal file upload.
        @param allow_none
                If allow_none is true then an input that is NONE or an empty string will be legal. If allow_none is false then NONE or an empty String will throw a ValidationException.
        @param error_list
                If validation is in error, resulting error will be stored in the error_list by context

        @throws IntrusionException
        """
        raise NotImplementedError()

    def is_valid_http_request(self, request):
        """
        Validate the current HTTP request by comparing parameters, headers, and cookies to a predefined whitelist of allowed
        characters. See the SecurityConfiguration class for the methods to retrieve the whitelists.

        @return true, if is a valid HTTP request

        @throws IntrusionException
        """
        raise NotImplementedError()

    def assert_is_valid_http_request(self, request):
        """
        Validates the current HTTP request by comparing parameters, headers, and cookies to a predefined whitelist of allowed
        characters. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
        will generate a descriptive IntrusionException.

        @throws ValidationException
        @throws IntrusionException
        """
        raise NotImplementedError()

    def is_valid_list_item(self, context, input_, list_):
        """
        Returns true if input is a valid list item.

        @param context
                A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
        @param input_
                The value to search 'list' for.
        @param list_
                The list to search for 'input'.

        @return true, if 'input' was found in 'list'.

        @throws IntrusionException
        """
        raise NotImplementedError()

    def get_valid_list_item(self, context, input_, list_, error_list=None):
        """
        Returns the list item that exactly matches the canonicalized input. Invalid or non-matching input
        will generate a descriptive ValidationException, and input that is clearly an attack
        will generate a descriptive IntrusionException. Instead of throwing a ValidationException
        on error, this variant will store the exception inside of the ValidationErrorList.

        @param context
                A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
        @param input_
                The value to search 'list' for.
        @param list_
                The list to search for 'input'.
        @param error_list
                If validation is in error, resulting error will be stored in the error_list by context

        @return The list item that exactly matches the canonicalized input.

        @throws IntrusionException
        """
        raise NotImplementedError()

    def is_valid_http_request_parameter_set(self, context, required, optional):
        """
        Returns true if the parameters in the current request contain all required parameters and only optional ones in addition.

        @param context
                A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
        @param required
                parameters that are required to be in HTTP request
        @param optional
                additional parameters that may be in HTTP request

        @return true, if all required parameters are in HTTP request and only optional parameters in addition.  Returns false if parameters are found in HTTP request that are not in either set (required or optional), or if any required parameters are missing from request.

        @throws IntrusionException
        """
        raise NotImplementedError()

    def assert_is_valid_http_request_parameter_set(self, context, required, optional, error_list=None):
        """
        Validates that the parameters in the current request contain all required parameters and only optional ones in
        addition. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
        will generate a descriptive IntrusionException. Instead of throwing a ValidationException on error,
        this variant will store the exception inside of the ValidationErrorList.

        @param context
                A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
        @param required
                parameters that are required to be in HTTP request
        @param optional
                additional parameters that may be in HTTP request
        @param error_list
                If validation is in error, resulting error will be stored in the error_list by context

        @throws IntrusionException
        """
        raise NotImplementedError()

    def is_valid_printable(self, context, input_, max_length, allow_none):
        """
        Returns true if input contains only valid printable ASCII characters.

        @param context
                A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
        @param input_
                data to be checked for validity
        @param max_length
                Maximum number of bytes stored in 'input'
        @param allow_none
                If allow_none is true then an input that is NONE or an empty string will be legal. If allow_none is false then NONE or an empty String will throw a ValidationException.

        @return true, if 'input' is less than max_length and contains only valid, printable characters

        @throws IntrusionException
        """
        raise NotImplementedError()

    def get_valid_printable(self, context,
                                input_,
                                max_length,
                                allow_none,
                                error_list=None):
        """
        Returns canonicalized and validated printable characters as a byte array. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
        will generate a descriptive IntrusionException.

         @param context
                A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
         @param input_
                data to be returned as valid and printable
         @param max_length
                Maximum number of bytes stored in 'input'
         @param allow_none
                If allow_none is true then an input that is NONE or an empty string will be legal. If allow_none is false then NONE or an empty String will throw a ValidationException.

         @return a byte array containing only printable characters, made up of data from 'input'

         @throws ValidationException
        """
        raise NotImplementedError()

    def is_valid_redirect_location(self, context, input_, allow_none):
        """
        Returns true if input is a valid redirect location, as defined by "ESAPI.conf.settings".

        @param context
                A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
        @param input_
                redirect location to be checked for validity, according to rules set in "ESAPI.conf.settings"
        @param allow_none
                If allow_none is true then an input that is NONE or an empty string will be legal. If allow_none is false then NONE or an empty String will throw a ValidationException.

        @return true, if 'input' is a valid redirect location, as defined by "ESAPI.conf.settings", false otherwise.

        @throws IntrusionException
        """
        raise NotImplementedError()

    def get_valid_redirect_location(self, context, input_, allow_none, error_list=None):
        """
        Returns a canonicalized and validated redirect location as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
        will generate a descriptive IntrusionException. Instead of throwing a ValidationException
        on error, this variant will store the exception inside of the ValidationErrorList.

        @param context
                A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
        @param input_
                redirect location to be returned as valid, according to encoding rules set in "ESAPI.conf.settings"
        @param allow_none
                If allow_none is true then an input that is NONE or an empty string will be legal. If allow_none is false then NONE or an empty String will throw a ValidationException.
        @param error_list
                If validation is in error, resulting error will be stored in the error_list by context

        @return A canonicalized and validated redirect location, as defined in "ESAPI.conf.settings"

        @throws IntrusionException
        """
        raise NotImplementedError()

    def safe_read_line(self, input_stream, max_length):
        """
        Reads from an input stream until end-of-line or a maximum number of
        characters. This method protects against the inherent denial of service
        attack in reading until the end of a line. If an attacker doesn't ever
        send a newline character, then a normal input stream reader will read
        until all memory is exhausted and the platform throws an OutOfMemoryError
        and probably terminates.

        @param input_stream
                The InputStream from which to read data
        @param max_length
                Maximum characters allowed to be read in per line

        @return a String containing the current line of inputStream

        @throws ValidationException
        """
        raise NotImplementedError()


