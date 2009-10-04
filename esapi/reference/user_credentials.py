#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: The UserCredentials class holds the credentials used to authenticate
    a User.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

# Todo

class UserCredentials():
    """
    The UserCredentials class holds the credentials used to authenticate
    a User.
    
    Credentials are extremely important, and they must be guarded very well.
    
    When designing the Authenticator and User interfaces, we anticipated that
    User objects will be kept around while an end-user is using the
    application. We felt that keeping user credentials in memory for an
    extended period of time is an unncessary risk, and decided to create
    this class to mitigate that attack vector. While never storing credentials
    in memory is not feasible, we would like to minimize their exposure and
    keep them in a single location.
    
    This class will be used when authenticating users in the Authenticator
    and will be released afterwards to be garbage collected.
    """
    def __init__(self, uid):
        # A unique user ID
        self.uid = uid
        
        # List of password hashes for the user
        # The last index is the one currently in use
        self._password_hashes = []
        
    def get_hashed_password(self):
        """
        If the user has no password set, return None.
        Otherwise, return the hash of the current password.
        """
        if len(self._password_hashes) < 1:
            return None
        return self._password_hashes[-1]
        
    def change_password(self, new_hash):
        """
        Appends the new_hash to the list.
        """
        self._password_hashes.append(new_hash)
    
    def get_old_password_hashes(self):
        """
        Returns a tuple of old password hashes.
        """
        return tuple(self._password_hashes)
        
