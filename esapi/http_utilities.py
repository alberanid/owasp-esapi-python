#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: The HTTPUtilities interface is a collection of methods that provide 
    additional security related to HTTP requests, responses, sessions, cookies,
    headers, and logging.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

# Todo
# Update get_file_uploads's @return when know what happens with Java File objects.

class HTTPUtilities():
    """
    The HTTPUtilities interface is a collection of methods that provide
    additional security related methods to HTTP requests, responses, sessions,
    cookies, headers, and logging.
    
    @author: Craig Younkins (craig.younkins@owasp.org)
    """
    
    REMEMBER_TOKEN_COOKIE_NAME = "rtoken"
    MAX_COOKIE_LEN = 4096 # From RFC 2109
    MAX_COOKIE_PAIRS = 20 # From RFC 2109
    CSRF_TOKEN_NAME = "ctoken"
    ESAPI_STATE = "estate"
    SESSION_TOKEN_NAME = "JSESSIONID"
    
    PARAMETER = 0
    HEADER = 1
    COOKIE = 2
    
    def __init__(self):
        raise NotImplementedError()
    
    def add_cookie(self, response=None, **kwargs):
        """
        If response is None, response refers to the current response.
        
        This method is intended to be called with keyword arguments the same
        as Django or Pylons/WebOb set_cookie().
        
        add_cookie(key, value='', max_age=None, path='/', domain=None,
        secure=None, httponly=False, version=None, comment=None, expires=None)
        
        Adds a cookie to the response after ensuring that there are no encoded
        or illegal characters in the name and value. This method sets the
        secure and HttpOnly flags on the cookie if they are to be forced,
        according to SecurityConfiguration.get_force_secure_cookies() and
        get_force_http_only_cookies().
        
        @param response: Optional parameter to specify the response to add the
            cookie to. Defaults to the current response.
        """
        raise NotImplementedError()
            
    def add_csrf_token(self, href):
        """
        Adds the current user's CSRF token to the URL to prevent CSRF attacks.
        This method should be used on all URLs to be put into links and forms
        that the application generates.
        
        @param href: the URL to which the CSRF token will be appended
        @return: the updated URL with the CSRF token parameter added
        @see: L{esapi.user.get_csrf_token}
        """
        raise NotImplementedError()
        
    def add_header(self, name, value, response=None):
        """
        If response is None, response refers to the current response.
        
        Add a header to the response after ensuring that there are no encoded
        or illegal characters in the name and value. This implementation 
        follows the following recommendation: "A recipient MAY replace any
        linear white space with a single SP before interpreting the field value
        or forwarding the message downstream."
        
        @see: U{http://www.w3.org/Protocols/rfc2616/rfc2616-sec2.html#sec2.2}
        @param response: Optional response the header will be appended to.
            Defaults to the current response.
        @param name: the header name
        @param value: the value of the header
        """
        raise NotImplementedError()
        
    def assert_secure_request(self, request=None):
        """
        If request is None, request refers to the current request.
        
        Ensures that the request uses SSL and POST to protect any sensitive
        parameters in the querystring from being sniffed, logged, bookmarked, 
        included in the referrer header, etc...
        This method should be called for any request that contains sensitive
        data from a web form.
        
        @param request: Optional parameter to specify the request to check.
            Defaults to the current request.
        @raises AccessControlException: if security constraints are not met
        @see: L{HTTPUtilities.set_current_http}
        """
        raise NotImplementedError()
        
    def change_session_identifier(self, request=None):
        """
        If request is None, request refers to the current request.
        
        Invalidate the existing session after copying all of its content to a
        newly created session with a new session id.
        
        Note that this is different from logging out and creating a new session
        identifier that does not contain the existing session contents. Care
        should be taken to use this only when the existing session does not 
        contain hazardous contents.
        
        @param request: Optional parameter to specify the request. Defaults
            to the current request.
        @return: the new HTTPSession with a changed id
        @raises AuthenticationException:
        """
        raise NotImplementedError()
        
    def clear_current(self):
        """
        Clears the current HttpRequest and HttpResponse associated with the
        current thread.
        """
        raise NotImplementedError()
        
    def decrypt_hidden_field(self, encrypted):
        """
        Decrypts an encrypted hidden field value and returns the cleartext.
        
        @raises IntrusionException: If the field does not decrypt properly,
            indicating possible tampering.
        @param encrypted: the hidden field to decrypt
        @return: decrypted hidden field
        """
        raise NotImplementedError()
        
    def decrypt_query_string(self, encrypted):
        """
        Takes an encrypted querystring and returns a dictionary containing the
        original parameters.
        
        @param encrypted: the encrypted querystring
        @return: a dict containing the decrypted querystring
        @raises EncryptionException: when something goes wrong with decryption
        """
        raise NotImplementedError()
        
    def decrypt_state_from_cookie(self, request=None):
        """
        If request is None, request refers to the current request.
        
        Retrieves a dict of data from a cookie encrypted with
        encrypt_state_in_cookie().
        
        @param request: Optional parameter specifying the request to look for
            cookies in.
        @return: A dictionary containing the decrypted cookie state value
        @raises EncryptionException: when something goes wrong with decryption.
        """
        raise NotImplementedError()
        
    def encrypt_hidden_field(self, value):
        """
        Encrypts a hidden field for use in HTML.
        
        @param value: the cleartext value of the hidden field
        @return: the encrypted value of the hidden field
        @raises EncryptionException: when something goes wrong with encryption.
        """
        raise NotImplementedError()
        
    def encrypt_query_string(self, query):
        """
        Takes the querystring (everything after the question mark in the URL)
        and returns an encrypted string containing the parameters.
        
        @param query: the querystring to encrypt
        @return: encrypted querystring stored as string
        @raises EncryptionException: when something goes wrong with encryption.
        """
        raise NotImplementedError()
        
    def encrypt_state_in_cookie(self, cleartext, response=None):
        """
        If response is None, response refers to the current response.
        
        Stores the name-value pairs from the cleartext in an encrypted cookie.
        Generally the session is a better place to store state information,
        as it does not expose it to the user at all. If there is a requirement
        not to use sessions, or the data should be store across sessions (for
        a long time), the use of encrypted cookies is an effective way to 
        prevent the exposure.
        
        @param response: Optional parameter specifying the response to put the
            encrypted cookie in. Defaults to the current response.
        @param cleartext: a dictionary containing the state information.
        @raises EncryptionException: when something goes wrong in encryption.
        """
        raise NotImplementedError()
        
    def get_cookie(self, name, request=None):
        """
        If request is None, request refers to the current request.
        
        A safer way to access cookies. This method returns the canonicalized
        value of the named cookie after "global" validation against the general
        type defined in esapi.conf.settings. This should not be considered a
        replacement for more specific validation.
        
        @param request: Optional parameter to specify the request. Defaults to
            the current request.
        @param name: the name of the cookie
        @return: the requested cookie value
        """
        raise NotImplementedError()
        
    def get_csrf_token(self):
        """
        Returns the current user's CSRF token. If there is no current user then
        return None.
        
        @return: the current user's CSRF token.
        """
        raise NotImplementedError()
        
    def get_current_request(self):
        """
        Retrieves the current request.
        
        @return: the current request
        """
        raise NotImplementedError()
        
    def get_current_response(self):
        """
        Retrieves the current response.
        
        @return: the current response
        """
        raise NotImplementedError()
        
    def get_file_uploads(self, request=None, upload_dir=None, allowed_extensions=None):
        """
        Extract the uploaded files from multipart HTTP requests.
        Implementations must check the content to ensure that it is safe before
        making a permanent copy on the local filesystem. Checks should include
        length and content checks, possibly virus checking, and path and name
        checks. Refer to the file checking methods in Validator for more
        information.
        
        @param request: Optional parameter to specify the request. Defaults to
            the current request.
        @param upload_dir: Optional directory in which the uploaded file will
            be placed. Defaults to the default upload directory specified in
            esapi.conf.settings.
        @param allowed_extensions: An optional list of allowed extensions for 
            the files. Defaults to the setting provided by SecurityConfiguration's
            get_allowed_file_extensions() method.
            
        @return: the 
        @raises ValidationException: if the file fails validation.
        """
        raise NotImplementedError()
        
    def get_header(self, name, request=None):
        """
        If request is none, request refers to the current request.
        
        A safer way to access headers. This returns the canonicalized value
        of the named header after "global" validation against the general
        type defined in SecurityConfiguration settings. This should not be
        considered a replacement for more specific validation.
        
        @param request: Optional request to get the header from. Defaults to
            the current request.
        @param name: the name of the header
        @return: the requested header value
        @raises ValidationException: if the header fails validation
        """
        raise NotImplementedError()
        
    def get_parameter(self, name, request=None):
        """
        If request is None, request refers to the current request.
        
        A safer way to access parameters. This method returns the canonicalized
        value of the named parameter after "global" validation against the 
        general type defined in SecurityConfiguration(). This should not be
        considered a replacement for more specific validation.
        
        @param request: Optional request to get the parameter from. Defaults
            to the current request.
        @param name: the name of the parameter.
        @return: the requested parameter value.
        """
        raise NotImplementedError()
        
    def kill_all_cookies(self, request=None, response=None):
        """
        Kill all cookies received in the last request from the browser.
        Note that new cookies set by the application in this response may not
        be killed by this method.
        
        @param request: Optional request to act upon. Defaults to the current
            request.
        @param response: Optional response to act upon. Defaults to the current
            response.
        """
        raise NotImplementedError()
        
    def kill_cookie(self, name, request=None, response=None):
        """
        Kills the specified cookie by setting a new cookie that expires
        immediately. Note that this method does not delete new cookies that
        are being set by the application for this response.
        
        @param name: the name of the cookie
        @param request: Optional request to act upon. Defaults to the current
            request.
        @param response: Optional response to act upon. Defaults to the current
            response.
        """
        raise NotImplementedError()
        
    def log_http_request(self, request=None, logger=None, parameters_to_obfuscate=None):
        """
        Format the source IP address, URL, URL parameters, and all form
        parameters into a string suitable for the log file. 
        
        The list of parameters to obfuscate should be specified in order to 
        prevent sensitive sensitive information from being logged. If the list
        is not provided, then all parameters will be logged. If HTTP request 
        logging is done in a central place, the parameters_to_obfuscate could
        be made a configuration parameter. We include it here in case different
        parts of the application need to obfuscate different parameters.
        
        @param request: Optional request to act upon. Defaults to the current 
            request.
        @param logger: Optional logger to write the request to. Defaults to the
            current logger.
        @param parameters_to_obfuscate: the sensitive parameters
        """
        raise NotImplementedError()
        
    def send_redirect(self, location, response=None):
        """
        Performs a redirect to the given location. Beware that forwarding to
        publicly accessible resources can be dangerous, as the request will
        have already passed the URL based access control check. This method
        ensures that you can only forward to non-publicly accessible resources.
        
        @param location: the URL to forward to, including parameters
        @param response: Optional response to act upon. Defaults to the current
            response.
        """
        raise NotImplementedError()
        
    def set_content_type(self, response=None):
        """
        Set the content type character encoding header on every response in
        order to limit the ways in which input can be represented. This
        prevents malicious users from using encoding and multi-byte escape
        sequences to bypass input validation routines.
        
        Implementations of this method should set the content type header to 
        a safe value for your environment. The default is 
        text/html; charset=UTF-8 character encoding, which is the default in
        early versions of HTML and HTTP. See U{RFC 2047<http://ds.internic.net/rfc/rfc2045.txt>}
        for more information about character encoding and MIME.
        
        @param response: Optional response to act upon. Defaults to the current
            response.
        """
       
    def set_current_http(self, request, response):
        """
        Stores the current request and response so that they may be readily
        accessed throughout ESAPI (and elsewhere)
        
        @param request: the request
        @param response: the response
        """
        raise NotImplementedError()
        
    def set_header(self, name, value, response=None):
        """
        Add a header to the response after ensuring that there are no encoded
        or illegal characters in the name and value. "A recipient MAY replace
        any linear whitespace with a single SP before interpreting the field
        value or forwarding the message downstream."
        
        @see: U{RFC 2616<http://www.w3.org/Protocols/rfc2616/rfc2616-sec2.html#sec2.2>}
        @param name: the header's name
        @param value: the header's value
        @param response: Optional response to act upon. Defaults to the current
            response.
        """
        raise NotImplementedError()
        
    def set_no_cache_headers(self, response=None):
        """
        Set headers to protect sensitive information against being cached in
        the browser. Developers should make this call for any HTTP responses
        that contain any sensitive data that should not be cached within the
        browser or any intermediate proxies or caches. Implementations should
        set headers for the expected browsers. The safest approach is to set
        all relevant headers to their most restrictive setting. This include:
        
            - Cache-Control: no-store
            - Cache-Control: no-cache
            - Cache-Control: must-revalidate
            - Expires: -1
            
        Note that the header "pragma: no-cache" is intended only for use in
        HTTP requests, not HTTP responses. However, Microsoft has chosen to
        directly violate the standards, so we need to include that header 
        here. For more information, refer to the relevant standards:
        
            - U{HTTP/1.1 Cache-Control "no-cache"<http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.9.1>}
            - U{HTTP/1.1 Cache-Control "no-store"<http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.9.2>}
            - U{HTTP/1.0 Pragma "no-cache"<http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.32>}
            - U{HTTP/1.0 Expires<http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.21>}
            - U{IE 6 Caching Issues<http://support.microsoft.com/kb/937479>}
            - U{Microsoft directly violates specification for pragma: no-cache<http://support.microsoft.com/kb/234067>}
            - U{Firefox browser.cache.disk_cache_ssl<https://developer.mozilla.org/en/Mozilla_Networking_Preferences#Cache>}
            
        @param response: Optional response to act upon. Defaults to the current
            response.
        """
        raise NotImplementedError()
        
    def set_remember_token(self, password, max_age, domain, path, request=None, response=None):
        """
        Set a cookie containing the current user's remember me token for
        automatic authentication. The use of remember me tokens is generally
        not recommended, but this method will help do it as safely as possible.
        The user interface should warn the user that this should only be
        enabled on computers where no other users will have access.
        
        Implementations should save the user's remember me data in an encrypted
        cookie and send it to the user.
        Any old remember me cookie should be destroyed first. Setting this
        cookie should keep the user logged in until max_age passes, the
        password is changed, or the cookie is deleted.
        If the cookie exists for the current user, it should automatically
        be used by ESAPI to log the user in, if the data is valid and not
        expired.
        
        @param password: the user's password
        @param max_age: the length of time that the token should be valid for
            in relative seconds
        @param domain: the domain to restrict the token to or None
        @param path: the path to restrict the token to or None
        @param request: Optional request to act upon. Defaults to the current
            request.
        @param response: Optional response to act upon. Defaults to the current
            response.
        @return: Encrypted "Remember me" token stored as string
        """
        raise NotImplementedError()
        
    def verify_csrf_token(self, request=None):
        """
        Checks the CSRF token in the URL against the user's CSRF token and
        raises an IntrusionException if it is missing.
        
        @param request: Option request to act upon. Defaults to the current
            request.
        @raises IntrusionException: if CSRF token is missing or incorrect
        """
        raise NotImplementedError()
