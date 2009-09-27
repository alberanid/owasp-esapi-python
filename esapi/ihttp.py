#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: A set of interfaces for HTTP requests, responses, and sessions.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

"""
These are the expected interfaces of HTTP requests, responses, and sessions. Very naive sample implementations exist in esapi/test/http

To use these functions with your Python webapp, you must write adapters to your requests, responses, and sessions so that they conform to this interface.
"""

class IHttpRequest():
    """
    This is the interface that ESAPI uses to interact with HTTP request
    objects. To use this with a framework like Django or Pylons, an adapter
    must be written.
    
    Data values are examples.
    """
    
    def __init__(self):
        # A dictionary-like object containing the decoded HTTP GET parameters
        self.GET = {'pid' : '1'}
        
        # A dictionary-like object containing the decoded HTTP POST parameters
        self.POST = {'username' : 'bob'}
    
        # The full URL to which the request was directed
        self.url = "https://www.example.com/example/?pid=1&qid=test"
        
        # The path including querystring
        self.path = "/example/?pid=1&qid=test"
        
        # The HTTP method used in the request. Must be uppercase.
        # EX: 'GET' or 'POST'
        self.method = 'POST'
        
        # The session associated with the request, probably set by middleware
        self.session = None
        
        # The cookies available as a dictionary of string name -> Morsel
        # We need the Morsel object to expose the path and domain of client's
        # cookies so that we can clear them
        self.cookies = {}
        
        # The headers in a dictionary-like object
        # string name -> string value
        self.headers = { 'Accept-Language' : 'en-us' }
        
        # The IP address of the request originator
        self.remote_host = '127.0.0.1'
    
    def is_secure(self):
        """
        Returns True if the request was made securely. That is, it returns True
        if the request was made over SSL (HTTPS).
        """
        pass
        
class IHttpResponse():
    """
    This is the interface that ESAPI uses to interact with HTTP response
    objects. To use this with a framework like Django or Pylons, an adapter
    must be written.
    
    Data values are examples.
    """
    
    def __init__(self):
        # Headers as a dictionary-like object
        self.headers = {
            'Content-Type' : 'text/html; charset=utf-8' }
        
        # The cookies available as a dictionary of string name -> Morsel
        # We need the Morsel object to expose the path and domain of client's
        # cookies so that we can clear them
        self.cookies = {}
        
    def delete_cookie(self, key, path='/', domain=None):
        """
        Deletes a cookie from the client by setting the cookie to an empty
        string, and max_age=0 so it should expire immediately.
        """
        pass
        
    def set_cookie(self, **kwargs):
        """
        Sets a cookie on the client my creating a Morsel and adding it to the
        headers.
        """
        pass
    
        
class ISession():
    """
    This is the interface that ESAPI uses to interact with session
    objects. To use this with a framework like Django or Pylons, an adapter
    must be written.
    
    Data values are examples.
    """
    
    def __init__(self):
        # The session attributes
        self.attributes = {}
        
        # A unique session id
        self.id = 1
        
        # The time the session was last accessed as a datetime object
        self.last_accessed_time = None
        
    def invalidate(self):
        """
        Delete the session data and starts a new session.
        
        Proxied to flush() in Django, and invalidate() in Beaker.
        """
        pass
        
    def __getitem__(self, item):
        """
        Access the given item in the attribute list.
        """
        pass
        
    def __setitem__(self, key, value):
        """
        Sets a given value to the attribute dictionary using the key.
        """
        pass
        
    def items(self):
        """
        Get the attributes as a list of tuples.
        """
        pass
        
    def get(self, key, default):
        """
        Get the specified attribute from the attributes list, returning
        default if the key does not exist.
        """
        pass
        
