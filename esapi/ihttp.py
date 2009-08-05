class IHttpRequest():
    """
    This is the interface that ESAPI uses to interact with HTTP request
    objects. To use this with a framework like Django or Pylons, an adapter
    must be written.
    """
    
    def __init__(self):
        # A dictionary-like object containing the decoded HTTP GET parameters
        self.GET = None
        
        # A dictionary-like object containing the decoded HTTP POST parameters
        self.POST = None
    
        # The full URL to which the request was directed
        self.url = None
        
        # The HTTP method used in the request. Must be uppercase.
        # EX: 'GET' or 'POST'
        self.method = None
        
        # The session associated with the request, probably set by middleware
        self.session = None
        
        # The cookies available as a dictionary of string name -> Morsel
        # We need the Morsel object to expose the path and domain of client's
        # cookies so that we can clear them
        self.cookies = None
        
        # The headers in a dictionary-like object
        # string name -> string value
        self.headers = None
        
        # The IP address of the request originator
        self.remote_host = None
        
        # The Accept-Language header 
        self.accept_language = None
    
    def is_secure(self):
        """
        Returns True if the request was made securely. That is, it returns True
        if the request was made over SSL (HTTPS).
        """
        pass
        
class IHttpResponse():
    
    def __init__(self):
        # Headers as a dictionary-like object
        self.headers = None
        
        # The cookies available as a dictionary of string name -> Morsel
        # We need the Morsel object to expose the path and domain of client's
        # cookies so that we can clear them
        self.cookies = None
        
    def delete_cookie(self, key, path='/', domain=None):
        """
        Deletes a cookie from the client by setting the cookie to an empty
        string, and max_age=0 so it should expire immediately.
        """
        pass
        
    def set_cookie(self, **kwargs):
        pass
    
        
class ISession():
    
    def __init__(self):
        # The session attributes
        self.attributes = {}
        
    def invalidate(self):
        """
        Delete the session data and starts a new session.
        
        Proxied to flush() in Django, and invalidate() in Beaker.
        """
        pass
        