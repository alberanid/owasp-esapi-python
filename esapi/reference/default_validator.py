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

import os.path

from esapi.validator import Validator
from esapi.core import ESAPI

from esapi.codecs.html_entity import HTMLEntityCodec
from esapi.codecs.percent import PercentCodec

from esapi.exceptions import ValidationException

from esapi.reference.default_encoder import DefaultEncoder

from esapi.reference.validation.credit_card_validation_rule import CreditCardValidationRule
from esapi.reference.validation.date_validation_rule import DateValidationRule
from esapi.reference.validation.number_validation_rule import NumberValidationRule
from esapi.reference.validation.string_validation_rule import StringValidationRule

class DefaultValidator(Validator):
    """
    Reference implementation of the Validator interface. This implementation
    relies on the ESAPI Encoder, re's regex,
    and several other classes to provide basic validation functions. This library
    has a heavy emphasis on whitelist validation and canonicalization. All double-encoded
    characters, even in multiple encoding schemes, such as <PRE>&amp;lt;</PRE> or
    <PRE>%26lt;</PRE> or even <PRE>%25%26lt;</PRE> are disallowed.
    """
    
    MAX_PARAMETER_NAME_LENGTH = 100
    MAX_PARAMETER_VALUE_LENGTH = 65535
    
    file_validator = None
    
    def __init__(self, encoder=None):
        Validator.__init__(self)
        if encoder:
            self.encoder = encoder
        else:
            self.encoder = ESAPI.encoder()
            
        self.make_file_validator()
        
    def make_file_validator(self):
        if DefaultValidator.file_validator is not None:
            return
        DefaultValidator.file_validator = 'fail'
        file_codecs = [HTMLEntityCodec(), PercentCodec()]
        file_encoder = DefaultEncoder(file_codecs)
        DefaultValidator.file_validator = DefaultValidator( file_encoder )
        
    def is_valid_input(self, context, input_, type_, max_length, allow_none):
        try:
            self.get_valid_input( context, input_, type_, max_length, allow_none)
            return True
        except ValidationException:
            return False
            
    def get_valid_input(self, context, input_, type_, max_length, allow_none, error_list=None):
        rvr = StringValidationRule( type_, self.encoder )
        pattern = ESAPI.security_configuration().get_validation_pattern(type_)
        if pattern is not None:
            rvr.add_whitelist_pattern(pattern)
        else:
            rvr.add_whitelist_pattern(type_)
            
        rvr.set_maximum_length(max_length)
        rvr.set_allow_none(allow_none)
        return rvr.get_valid(context, input_)
        
    def is_valid_credit_card(self, context, input_, allow_none):
        try:
            self.get_valid_credit_card( context, input_, allow_none )
            return True
        except ValidationException:
            return False
            
    def get_valid_credit_card(self, context, input_, allow_none, errors=None):
        ccvr = CreditCardValidationRule("creditcard", self.encoder)
        ccvr.set_allow_none(allow_none)
        return ccvr.get_valid(context, input_, errors)
    
    def is_valid_date(self, context, input_, format_, allow_none):
        try:
            self.get_valid_date( context, input_, format_, allow_none )
            return True
        except ValidationException:
            return False
            
    def get_valid_date(self, context, input_, format_, allow_none, errors=None):
        dvr = DateValidationRule("SimpleDate", self.encoder, format_)
        dvr.set_allow_none(allow_none)
        return dvr.get_valid(context, input_, errors)
        
    def is_valid_number(self, context, num_type, input_, min_value, max_value, allow_none):
        try:
            self.get_valid_number(context, num_type, input_, min_value, max_value, allow_none)
            return True
        except ValidationException:
            return False
            
    def get_valid_number(self, context, num_type, input_, min_value, max_value, allow_none, errors=None):
        nvr = NumberValidationRule("number", num_type, self.encoder, min_value, max_value)
        nvr.set_allow_none(allow_none)
        return nvr.get_valid(context, input_, errors)
        
    def is_valid_directory_path(self, context, input_, parent_dir, allow_none):
        """
        Returns true if the directory path (not including a filename) is valid.
	  
        <p><b>Note:</b> On platforms that support symlinks, this function will 
        fail canonicalization if the directory path is a symlink. For example,
        on MacOS X, /etc is actually /private/etc. If you mean to use /etc, use
        its real path (/private/etc), not the symlink (/etc).</p>
        """
        try:
            self.get_valid_directory_path( context, input_, parent_dir, allow_none )
            return True
        except ValidationException:
            return False
            
    def get_valid_directory_path(self, context, input_, parent_dir, allow_none, errors=None):
        """
        Returns a canonicalized and validated directory path as a String. 
        
        <p><b>Note:</b> On platforms that support symlinks, this function will 
        fail canonicalization if the directory path is a symlink. For example,
        on MacOS X, /etc is actually /private/etc. If you mean to use /etc, use
        its real path (/private/etc), not the symlink (/etc).</p>
        """
        try:
            # Check that input_ is provided
            if self.is_empty(input_):
                if allow_none:
                    return None
                raise ValidationException( context + ": Input directory path required", "Input directory path required: context=" + context + ", input=''", context )
            
            # Check that parent_dir is provided
            if self.is_empty(parent_dir):
                raise ValidationException( context + ": Invalid directory name", "Parent directory required: context=" + context + ", input=" + input_ + ", parent_dir=''", context )
           
            ################################
            
            # Canonicalize input_
            # abspath - 
            # normpath - 
            # realpath - On windows, = abspath
            canonical_input2 = os.path.realpath(input_)
            canonical_input1 = DefaultValidator.file_validator.get_valid_input(context, canonical_input2, "DirectoryName", 255, False)
            canonical_input = os.path.normcase(canonical_input1)
            
            # Check that canonical matches input
            # On case-sensitive filesystems, normcase does nothing.
            # On case-insensitive filesystems, this normalizes case for the comparison
            if canonical_input != os.path.normcase(input_):
                raise ValidationException( context + ": Invalid directory name", "Invalid directory name does not match the canonical path: context=" + context + ", input=" + input_ + ", canonical=" + canonical_input, context )
                
            # Canonicalize parent_dir
            canonical_parent2 = os.path.realpath(parent_dir)
            canonical_parent1 = DefaultValidator.file_validator.get_valid_input(context, canonical_parent2, "DirectoryName", 255, False)
            canonical_parent = os.path.normcase(canonical_parent1)
            
            # Check that canonical matches parent_dir
            # On case-sensitive filesystems, normcase does nothing.
            # On case-insensitive filesystems, this normalizes case for the comparison
            if canonical_parent != os.path.normcase(parent_dir):
                raise ValidationException( context + ": Invalid directory name", "Invalid parent directory name does not match the canonical path: context=" + context + ", input=" + input_ + ", parent_dir=" + parent_dir + ", canonical_parent=" + canonical_parent, context )
                             
            ################################
                             
            # Check that the input dir exists on disk and is a directory
            if not os.path.isdir(canonical_input):
                raise ValidationException( context + ": Invalid directory name", "Invalid directory name does not exist: context=" + context + ", input=" + canonical_input, context )
        
            # Check that the parent dir exists on disk and is a directory
            if not os.path.isdir(canonical_parent):
                raise ValidationException( context + ": Invalid directory name", "Invalid parent directory name does not exist: context=" + context + ", parent_dir=" + canonical_parent, context )
                
            ###############################3
            
            # Check that the input_ starts with the parent_dir
            if not canonical_input.startswith(canonical_parent):
                raise ValidationException( context + ": Invalid directory name", "Input directory is not inside given parent directory: context=" + context + ", input=" + canonical_input + ", parent_dir=" + canonical_parent, context )
                
            return canonical_input
            
        except ValidationException, extra:
            if errors is not None:
                errors[context] = extra
            else:
                raise
            
    def is_valid_filename(self, context, input_, allow_none, allowed_extensions=None):
        try:
            self.get_valid_filename( context, input_, allow_none, allowed_extensions=allowed_extensions )
            return True
        except ValidationException:
            return False
            
    def get_valid_filename( self, context, input_, allow_none, error_list=None, allowed_extensions=None):
        try:
            if self.is_empty(input_):
                if allow_none:
                    return None
                raise ValidationException( context + ": Input file name required", "Input required: context=" + context + ", input=" + input_, context )
            
            # Do basic validation
            self.get_valid_input(context, input_, "Filename", 255, True)
            
            # Verify extensions
            if not allowed_extensions:
                allowed_extensions = ESAPI.security_configuration().get_allowed_file_extensions()
                
            file_ext = os.path.splitext(input_)[1]
            file_ext = file_ext.lower()
            if file_ext in allowed_extensions:
                return input_
            else:
                raise ValidationException( context + ": Invalid file name does not have valid extension ( "+ str(allowed_extensions) +")", "Invalid file name does not have valid extension ( "+ str(allowed_extensions) +"): context=" + context+", input=" + input_, context )
            
        except ValidationException, extra:
            if error_list is not None:
                error_list[context] = extra
            else:
                raise
                
    def is_valid_file_content(self, context, input_, max_bytes, allow_none):
        """
        This implementation only verifies that the file size is less than or
        equal to the max_bytes specified in the parameter and less than the
        max bytes specified in ESAPI.conf.settings.py.
        """
        try:
            self.get_valid_file_content( context, input_, max_bytes, allow_none )
            return True
        except ValidationException:
            return False
            
    def get_valid_file_content(self, context, input_, max_bytes, allow_none, errors=None ):
        """
        This implementation only verifies that the file size is less than or
        equal to the max_bytes specified in the parameter and less than the
        max bytes specified in ESAPI.conf.settings.py.
        """
        try:
            if self.is_empty(input_):
                if allow_none:
                    return None
                raise ValidationException( context + ": Input required", "Input required: context=" + context + ", input=" + input_, context )
        
            esapi_max_bytes = ESAPI.security_configuration().get_allowed_file_upload_size()
            if len(input_) > esapi_max_bytes:
                raise ValidationException( context + ": Invalid file content can not exceed " + str(esapi_max_bytes) + " bytes", "Exceeded ESAPI max length", context )
            if len(input_) > max_bytes:
                raise ValidationException( context + ": Invalid file content can not exceed " + str(max_bytes) + " bytes", "Exceeded maxBytes ( " + str(len(input_)) + ")", context )
            
            return input_
        
        except ValidationException, extra:
            if errors is not None:
                errors[context] = extra
            else:
                raise
                
    def is_valid_file_upload(self, context,
                                directory_path,
                                parent,
                                filename,
                                content,
                                max_bytes,
                                allow_none):
        return (self.is_valid_filename( context, filename, allow_none ) and
                self.is_valid_directory_path( context, directory_path, parent, allow_none ) and
                self.is_valid_file_content( context, content, max_bytes, allow_none ))

    def assert_valid_file_upload(self, context,
                                      directory_path,
                                      parent,
                                      filename,
                                      content,
                                      max_bytes,
                                      allow_none,
                                      error_list=None):
        self.get_valid_filename( context, filename, allow_none ) 
        self.get_valid_directory_path( context, directory_path, parent, allow_none ) 
        self.get_valid_file_content( context, content, max_bytes, allow_none )
        
    def is_valid_http_request(self, request):
        raise NotImplementedError()

    def assert_is_valid_http_request(self, request):
        raise NotImplementedError()
        
    def is_valid_http_request_parameter_set(self, context, required, optional):
        raise NotImplementedError()

    def assert_is_valid_http_request_parameter_set(self, context, required, optional, error_list=None):
        raise NotImplementedError()
        
    def is_valid_redirect_location(self, context, input_, allow_none):
        return self.is_valid_input( context, input_, "Redirect", 512, allow_none)
        
    def get_valid_redirect_location(self, context, input_, allow_none, error_list=None):
        return self.get_valid_input( context, input_, "Redirect", 512, allow_none, error_list )
                                      
    def safe_read_line(self, input_stream, max_length):
        return input_stream.readline(max_length)
        
    def is_valid_safe_html(self, context, input_, max_length, allow_none):
        raise NotImplementedError()
        
    def get_valid_safe_html(self, context,
                                 input_,
                                 max_length,
                                 allow_none,
                                 error_list=None):
        raise NotImplementedError()
                                      
    def is_empty(self, obj):
        """
        Checks if the given obj is None or empty.
        """
        if obj is None or len(obj) == 0:
            return True
            
        if isinstance(obj, str) and len(obj.strip()) == 0:
            return True
            
        return False