#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: A mock session used for testing.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

# Todo

class MockSession():
    count = 0
    
    def __init__(self):
        self.attributes = {}
        
        MockSession.count += 1
        self.id = MockSession.count
        
    def delete_cookie(self, key, path='/', domain=None):
        """
        Deletes a cookie from the client by setting the cookie to an empty
        string, and max_age=0 so it should expire immediately.
        """
        pass
        
    def __getitem__(self, item):
        return self.attributes[item]
        
    def __setitem__(self, key, value):
        self.attributes[key] = value
        
    def items(self):
        return self.attributes.items()