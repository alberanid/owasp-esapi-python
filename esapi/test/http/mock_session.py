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

from datetime import datetime

class MockSession():
    count = 0
    
    def __init__(self):
        self.attributes = {}
        
        MockSession.count += 1
        self.id = MockSession.count
        
        self.creation_time = datetime.now()
        self.last_accessed_time = datetime.now()
        
    def invalidate(self):
        """
        Invalidates the session.
        """
        MockSession.count += 1
        self.id = MockSession.count
        
    def __getitem__(self, item):
        self._update_accessed_time()
        return self.attributes[item]
        
    def __setitem__(self, key, value):
        self._update_accessed_time()
        self.attributes[key] = value
        
    def items(self):
        self._update_accessed_time()
        return self.attributes.items()
        
    def get(self, key, default):
        self._update_accessed_time()
        if self.attributes.has_key(key):
            return self.attributes[key]
        
        return default
        
    def _update_accessed_time(self):
        self.last_accessed_time = datetime.now()