#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: A mock HTTP response used for testing.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

# Todo

from Cookie import Morsel

class MockHttpResponse():
    
    def __init__(self):
        self.headers = {}
        self.cookies = {}
        
    def delete_cookie(self, key, path='/', domain=None):
        """
        Deletes a cookie from the client by setting the cookie to an empty
        string, and max_age=0 so it should expire immediately.
        """
        if self.cookies.has_key(key):
            self.cookies[key].value = ''
            self.cookies[key]['max-age'] = 0
        else:
            m = Morsel()
            m.key = key
            m.value = ''
            m.path = path
            m.domain = domain
            m['max-age'] = 0
            self.cookies[key] = m
        
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
        
