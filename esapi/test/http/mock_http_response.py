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

class MockHttpResponse():
    
    def __init__(self):
        self.headers = {}
        
    def delete_cookie(self, key, path='/', domain=None):
        """
        Deletes a cookie from the client by setting the cookie to an empty
        string, and max_age=0 so it should expire immediately.
        """
        pass