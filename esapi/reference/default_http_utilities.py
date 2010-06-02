#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: Reference implementation of HTTPUtilities interface.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

# Todo

import Cookie
from datetime import datetime, timedelta

from esapi.core import ESAPI
from esapi.translation import _
from esapi.validation_error_list import ValidationErrorList
from esapi.logger import Logger
from esapi.http_utilities import HTTPUtilities

from esapi.exceptions import ValidationException, AccessControlException, EncryptionException, EncodingException, IntegrityException, IntrusionException

class DefaultHTTPUtilities(HTTPUtilities):
    """
    The default implementation of the HTTPUtilities class.
    
    Note: get_file_uploads() and send_redirect() are not implemented because
    they are highly dependent upon the framework.
    
    @author: Craig Younkins (craig.younkins@owasp.org)
    """
    
    max_bytes = ESAPI.security_configuration().get_allowed_file_upload_size()
    
    def __init__(self):
        self.logger = ESAPI.logger("HTTPUtilities")
        self.current_request = None
        self.current_response = None
    
    def add_cookie(self, response=None, **kwargs):
        if response is None:
            response = self.current_response
            
        if not kwargs.has_key('secure'):
            if ESAPI.security_configuration().get_force_secure_cookies():
                kwargs['secure'] = True
                
        if not kwargs.has_key('httponly'):
            if ESAPI.security_configuration().get_force_http_only_cookies():
                kwargs['httponly'] = True

        # Validate the key and value
        errors = ValidationErrorList()
        safe_key = ESAPI.validator().get_valid_input("cookie name", 
            kwargs['key'], "HTTPCookieName", 50, False, errors)
        safe_value = ESAPI.validator().get_valid_input("cookie value",
            kwargs['value'], "HTTPCookieValue", 5000, False, errors)
            
        kwargs['key'] = safe_key
        kwargs['value'] = safe_value
            
        # If no errors, set the cookie
        if len(errors) == 0:
            response.set_cookie(**kwargs)
            return
        
        # Error!
        self.logger.warning( Logger.SECURITY_FAILURE, 
            _("Attempt to add unsafe data to cookie (skip mode). Skipping cookie and continuing.") )
       
    def add_csrf_token(self, href):
        user = ESAPI.authenticator().current_user
        if user.is_anonymous():
            return href
            
        # If there are already parameters, append with an &, otherwise append
        # with a ?
        token = self.CSRF_TOKEN_NAME + "=" + user.csrf_token
        if href.find('?') == -1:
            # No params yet
            return href + "?" + token
        else:
            # href has params already
            return href + "&" + token
        
    def add_header(self, name, value, response=None):
        if response is None:
            response = self.current_response
            
        stripped_name = name.strip()
        stripped_value = value.strip()
        
        try:
            safe_name = ESAPI.validator().get_valid_input("addHeader",
                stripped_name, "HTTPHeaderName", 20, False)
            safe_value = ESAPI.validator().get_valid_input("addHeader",
                stripped_value, "HTTPHeaderValue", 500, False)
            response.headers[safe_name] = safe_value
        except ValidationException, extra:
            self.logger.warning( Logger.SECURITY_FAILURE,
                _("Attempt to add invalid header denied"), extra )
        
    def assert_secure_request(self, request=None):
        if request is None:
            request = self.current_request
            
        if not request.is_secure():
            raise AccessControlException( _("Insecure request received"),
                _("Receieved non-SSL request: %(url)s") %
                {'url' : request.url})
                
        req_method = "POST"
        if request.method != req_method:
            raise AccessControlException(
                _("Insecure request received"),
                _("Receieved request using %(method)s when only %(req_method)s is allowed") %
                {'method' : request.method,
                 'req_method' : req_method} )
        
    def change_session_identifier(self, request=None):      
        temp = {}
        for key, value in request.session.items():
            temp[key] = value
            
        # Kill old session and create a new one
        user = ESAPI.authenticator().current_user
        user.remove_session(request.session)
        
        request.session.invalidate()
        user.add_session(request.session)
        
        # Copy back the session content
        for key, value in temp.items():
            request.session[key] = value
            
        return request.session
        
    def clear_current(self):
        self.current_request = None
        self.current_response = None
        
    def decrypt_hidden_field(self, encrypted):
        try:
            return ESAPI.encryptor().decrypt(encrypted)
        except EncryptionException, extra:
            raise IntrusionException( 
                _("Invalid request"),
                _("Tampering detected. Hidden field data did not decrypt properly."), extra )
        
    def decrypt_query_string(self, encrypted):
        plaintext = ESAPI.encryptor().decrypt(encrypted)
        return self.query_to_dict(plaintext)
        
    def decrypt_state_from_cookie(self, request=None):
        if request is None:
            request = self.current_request
            
        try:
            encrypted = self.get_cookie( self.ESAPI_STATE, request )
            if encrypted is None:
                return {}
            plaintext = ESAPI.encryptor().decrypt(encrypted)
            return self.query_to_dict(plaintext)
        except ValidationException, extra:
            return None
            
    def query_to_dict(self, text):
        if '?' == text[0]:
            text = text[1:]
        
        d = {}
        
        for pair in text.split('&'):
            key, value = pair.split('=')
            d[key] = value
                
        return d
        
    def encrypt_hidden_field(self, value):
        return ESAPI.encryptor().encrypt(value)
        
    def encrypt_query_string(self, query):
        return ESAPI.encryptor().encrypt(query)
        
    def encrypt_state_in_cookie(self, cleartext_map, response=None):
        if response is None:
            response = self.current_response
            
        buf = ''
        for key, value in cleartext_map.items():
            if buf != '':
                buf += '&'
        
            try:
                key = ESAPI.encoder().encode_for_url( key )
                value = ESAPI.encoder().encode_for_url( value )
                buf += "%s=%s" % (key, value)
            except EncodingException, extra:
                self.logger.error( Logger.SECURITY_FAILURE,
                    _("Problem encrypting state in cookie - skipping entry"),
                    extra=extra )
                    
        encrypted = ESAPI.encryptor().encrypt(buf)
        if len(encrypted) > self.MAX_COOKIE_LEN:
            self.logger.error( Logger.SECURITY_FAILURE,
                _("Problem encrypting state in cookie because of max cookie length") )
            raise EncryptionException( _("Encryption Exception"),
                _("Encrypted cookie state length of %(len)s is longer than allowed %(allowed)s.") % 
                {'len' : len(encrypted),
                 'allowed' : self.MAX_COOKIE_LEN} )
                 
        self.add_cookie( response, key=self.ESAPI_STATE, value=encrypted )
        
    def get_cookie(self, name, request=None):
        if request is None:
            request = self.current_request
            
        morsel = request.cookies.get(name, None)
        
        if morsel is None:
            return None
            
        return ESAPI.validator().get_valid_input(
            "HTTP cookie value: %s " % morsel.value, 
            morsel.value, "HTTPCookieValue", 1000, False )
        
    def get_csrf_token(self):
        user = ESAPI.authenticator().current_user
        if user is None:
            return None
        return user.csrf_token
        
    def get_current_request(self):
        return self.current_request
        
    def get_current_response(self):
        return self.current_response
        
    def get_file_uploads(self, request=None, upload_dir=None, allowed_extensions=None):
        raise NotImplementedError()
        
    def get_header(self, name, request=None):
        if request is None:
            request = self.current_request
            
        value = request[name]
        return ESAPI.validator().get_valid_input(
            _("HTTP header value: %(value)s") % 
            {'value' : value},
            value, "HTTPHeaderValue", 150, False )
        
    def get_parameter(self, name, request=None):
        if request is None:
            request = self.current_request
            
        raw = None
        if name in request.POST:
            raw = request.POST[name]
        elif name in request.GET:
            raw = request.GET[name]
        
        return ESAPI.validator().get_valid_input(
            _("HTTP parameter value: %(val)s") %
            {'val' : raw},
            raw, "HTTPParameterValue", 2000, False )
        
    def kill_all_cookies(self, request=None, response=None):
        if request is None:
            request = self.current_request
            
        if response is None:
            response = self.current_response
            
        for name in request.cookies:
            self.kill_cookie(name, request, response)
        
    def kill_cookie(self, name, request=None, response=None):
        if request is None:
            request = self.current_request
            
        if response is None:
            response = self.current_response
            
        path = '/'
        domain = None
        if request.cookies.has_key(name):
            path = request.cookies[name]['path']
            domain = request.cookies[name]['domain']
            
        response.delete_cookie(name, path, domain)
        
    def log_http_request(self, request=None, logger=None, parameters_to_obfuscate=None):
        if request is None:
            request = self.current_request
        
        if logger is None:
            logger = self.logger
            
        if parameters_to_obfuscate is None:
            parameters_to_obfuscate = []
            
        parameters_to_obfuscate.append(self.SESSION_TOKEN_NAME)
            
        param_string = ''
        for list_ in [request.GET, request.POST]:
            for key, value in list_.items():
                if param_string != '':
                    param_string += '&'
                    
                if value in parameters_to_obfuscate:
                    value = '*' * 8
                
                param_string += "%s=%s" % (key, value)
                
        for morsel in request.cookies.values():
            if morsel.value in parameters_to_obfuscate:
                value = '*' * 8
            
            param_string += "+%s=%s" % (morsel.key, morsel.value)
            
        msg = ( "%(method)s %(url)s%(params)s" % 
            {'method' : request.method,
             'url' : request.url,
             'params' : '?' + param_string if param_string else ''} )
        logger.info(Logger.SECURITY_SUCCESS, msg)
        
    def send_redirect(self, location, response=None):
        """
        This is highly dependent upon the framework being used, so I leave
        it to you to implement.
        """
        raise NotImplementedError()
        
    def set_content_type(self, response=None):
        if response is None:
            response = self.current_response
            
        response.content_type = ESAPI.security_configuration().get_response_content_type()
       
    def set_current_http(self, request, response):
        self.current_request = request
        self.current_response = response
        
    def set_header(self, name, value, response=None):
        if response is None:
            response = self.current_response
            
        try:
            safe_name = ESAPI.validator().get_valid_input("setHeader", name.strip(), "HTTPHeaderName", 20, False)
            safe_value = ESAPI.validator().get_valid_input("setHeader", value.strip(), "HTTPHeaderValue", 500, False)
            response[safe_name] = safe_value
        except ValidationException, extra:
            self.logger( Logger.SECURITY_FAILURE,
                _("Attempt to set invalid header denied"),
                extra )
        
    def set_no_cache_headers(self, response=None):
        if response is None:
            response = self.current_response
           
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        
    def set_remember_token(self, password, max_age, domain, path, request=None, response=None):
        if request is None:
            request = self.current_request
            
        if response is None:
            response = self.current_response
            
        user = ESAPI.authenticator().current_user
        try:
            self.kill_cookie(self.REMEMBER_TOKEN_COOKIE_NAME, request, response)
            # Seal already contains random data
            clear_token = user.account_name + "|" + password
            expiry = datetime.now() + timedelta(seconds=max_age)
            crypt_token = ESAPI.encryptor().seal(clear_token, expiry)
            morsel = Cookie.Morsel()
            morsel.value = crypt_token
            morsel['max-age'] = max_age
            morsel['domain'] = domain
            morsel['path'] = path
            response.cookies[self.REMEMBER_TOKEN_COOKIE_NAME] = morsel
            
            self.logger.info( Logger.SECURITY_SUCCESS,
                _("Enabled remember me token for %(user)s") %
                {'user' : user.account_name} )
            return crypt_token
        except IntegrityException, extra:
            self.logger.warning( Logger.SECURITY_FAILURE,
                _("Attempt to set remember me token failed for %(user)s") %
                {'user' : user.account_name}, extra )
        
    def verify_csrf_token(self, request=None):
        if request is None:
            request = self.current_request
            
        user = ESAPI.authenticator().current_user
        
        # check if user authenticated with this request - no CSRF protection required
        if request.headers.has_key(user.csrf_token):
            return
        
        token = request.GET.get(self.CSRF_TOKEN_NAME)
        if user.csrf_token != token:
            raise IntrusionException(
                _("Authentication failed"),
                _("Possibly forged HTTP request without proper CSRF token detected") )
