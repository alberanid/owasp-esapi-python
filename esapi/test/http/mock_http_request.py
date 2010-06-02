#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: A mock HTTP request used for testing.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

# Todo

from mock_session import MockSession
from Cookie import Morsel

class MockHttpRequest():
    def __init__(self):
        # A dictionary-like object containing the decoded HTTP GET parameters
        self.GET = {}
        
        # A dictionary-like object containing the decoded HTTP POST parameters
        self.POST = {}
    
        # The full URL to which the request was directed
        self.url = "https://www.example.com/example/?pid=1&qid=test"
        
        self.path = "/example/?pid=1&qid=test"
        
        # The HTTP method used in the request. Must be uppercase.
        # EX: 'GET' or 'POST'
        self.method = 'POST'
        
        # The session associated with the request, probably set by middleware
        self.session = MockSession()
        
        # The cookies available as a dictionary of string name -> Morsel
        # We need the Morsel object to expose the path and domain of client's
        # cookies so that we can clear them
        self.cookies = {}
        
        # The headers in a dictionary-like object
        # string name -> string value
        self.headers = {
            'Accept-Language' : 'en-us', }
        
        self.remote_host = '64.14.103.52'
    
    def is_secure(self):
        """
        Returns True if the request was made securely. That is, it returns True
        if the request was made over SSL (HTTPS).
        """
        return self.url.startswith("https")

    def set_cookie(self, **kwargs):
        key = kwargs['key']
        m = Morsel()
        m.key = key
        m.value = kwargs['value']
        m.coded_value = kwargs['value']
        for k, v in kwargs.items():
            try:
                m[k] = v
            except:
                pass
        self.cookies[key] = m
        self.headers['Set-Cookie'] = str(m)
