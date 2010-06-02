#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: The Authenticator interface defines a set of methods for generating
    and handling account credentials and session identifiers.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

# Todo

class Authenticator():
    """
    The Authenticator interface defines a set of methods for generating and 
    handling account credentials and session identifiers. The goal of this
    interface is to encourage developers to protect credentials from disclosure
    to the maximum extent possible.
    
    One possible implementation relies on the use of thread local variables
    to store the current user's identity. The application is responsible for
    calling set_current_user() as soon as possible after each HTTP request is
    received. The value of get_current_user() is used in several places in this
    API. This eliminates the need to pass a user object to methods throughout the
    library. For example, all of the logging, access control, and exception calls
    need access to the currently logged in user.
    
    The goal is to minimize the responsibility of the developer for 
    authentication. In this example, the user simply calls authenticate with 
    the current request and the name of the parameters containing the username 
    and password. The implementation should verify the password if necessary,
    create a session if necessary, and set the user as the current user.
    """
    def __init__(self):       
        # The current user as a User object
        self.current_user = None
        
    def clear_current(self):
        """
        Clears the current user. This allows the thread to be reused safely.
        
        This clears all threadlocal variables from the thread. This should
        ONLY be called after all possible ESAPI operations have concluded.
        If you clear too early, many calls will fail, including logging,
        which requires the user identity.
        """
        raise NotImplementedError()
        
    def login(self, request=None, response=None):
        """
        Authenticates the user's credentials from the HttpRequest if 
        necessary, creates a session if necessary, and sets the user as the
        current user.
        
        The implementation should do the following:
            1. Check if the user is already store in the session
                A. If so, check that the session absolute and inactivity
                   timeouts have not expired.
                B. Step 2 may not be required if 1A has been satisfied.
            2. Verify user credentials
            3. Set the last host of the user 
               (eg. user.set_last_host_address(address))
            4. Verify that the request is secure
            5. Verify the user account is allowed to be logged in
                A. Verify user is not disabled, expired, or locked
            6. Assign user to session variable
        
        @param request: Optional parameter to specify the request. Defaults to
            the current request.
        @param response: Optional parameter to specify the response. Defaults
            to the current response.
        @return: the user
        @raises AuthenticationException: if credentials are not verified, or
            if the account is disabled, locked, expired, or timed out.
        """
        raise NotImplementedError()
        
    def verify_password(self, user, password_hash):
        """
        Verify that the supplied password matches the password for this user.
        Password should be stored as a hash. It is recommended you use the
        hash_password(password, account_name) method in this class.
        This method is typically used for "reauthentication" for the most 
        sensitive functions, such as
            - Transactions
            - Changing email address
            - Changing other sensitive account information
            
        @param user: the user that requires verification
        @param password_hash: the hashed password
        @return: True if the password is correct for the given user. False
            otherwise
        """
        raise NotImplementedError()
        
    def logout(self, user=None):
        """
        Logs out the user.
        
        @param user: Optional user to logout. Defaults to the current user.
        """
        raise NotImplementedError()
        
    def create_user(self, account_name, password1, password2):
        """
        Creates a new user with the information provided. Implementations
        should check account_name and password for proper format and
        strength against brute force attacks.
        
        Two copies of the password are required to encourage user interface
        designers to include a "re-type password" field in their forms. 
        Implementations if this method should verify that both are the same.
        
        @param account_name: the account name of the new user.
        @param password1: the password of the new user.
        @param password2: the password of the new user. This is used to
            to protect against typos.
        @return: the user that has been created.
        @raises AuthenticationException: if user creation fails.
        """
        raise NotImplementedError()
        
    def generate_strong_password(self):
        """
        Generate a strong password. Implementations should use a large
        character set that does not include confusing characters, such as
        i I 1 l O o and 0. There are many algorithms to generate strong
        memorable passwords that have been studied.
        
        @return: a strong password as a string
        """
        raise NotImplementedError()
        
    def change_password(self, user, current_password, new_password1, new_password2):
        """
        Changes the password for the specified user. This requires the
        current password, as well as the password to replace it with.
        The new password should be checked against old hashes to be sure an
        old password isn't being reused. 
        
        Password strength should also be verified. This new password must be
        repeated to ensure that the user has typed it in correctly.
        
        @param user: the user to change the password for
        @param current_password: the current password for the specified user
        @param new_password1: the new password
        @param new_password2: the new password again.
        @raises AuthenticationException: if any errors occur
        """
        raise NotImplementedError()
        
    def get_user(self, account_name):
        """
        Return a user matching the provided account_name.
        
        If account_name is not given, or the specified
        user cannot be found, None should be returned.
        
        @param account_name: the account name
        @return: the matching user object, or None
        """
        raise NotImplementedError()
    
    def hash_password(self, password, account_name):
        """
        Returns a string of the hashed password, using the account_name as a
        salt. The salt helps to prevent against "rainbow" table attacks where
        the attacker pre-calculates hashes for known strings.
        
        This method specifies the use of the user's account name as the salt
        value. The Encryptor.hash method can be used if a different salt is
        required.
        
        @param password: the password to hash
        @param account_name: the account name to use as the salt
        @return: the hashed password
        @raises EncryptionException: if something goes wrong when hashing
        """
        raise NotImplementedError()
        
    def remove_user(self, account_name):
        """
        Removes the account associated with the given account_name. 
        
        @param account_name: the account name of the account to remove
        @raises AuthenticationException: Will be raised if the user does not
            exist.
        """
        raise NotImplementedError()
        
    def verify_account_name_strength(self, account_name):
        """
        Ensures that the account name passes site-specific complexity 
        requirements, like minimum length.
        
        @param account_name: the account name
        @raises AuthenticationException: if the account name does not meet
            complexity requirements.
        """
        raise NotImplementedError()
        
    def verify_password_strength(self, new_password, old_password=None):
        """
        Ensures that the password meets site-specific complexity requirements,
        like length or character set requirements. This method optionally
        takes in the old password so that the algorithm can analyze the new
        password to see if the two are too similar. Note that this has to be
        invoked when the user has entered the old password, as the list
        of old credentials stored by ESAPI is all hashed.
        
        It is a good idea for implementations to compare the password for
        similarity to dictionary words. This is NOT done in the default
        implementation.
        
        @param new_password: the new password
        @param old_password: Optional old password. If provided, similarity
            to the new password will be analyzed.
        @raises AuthenticationException: if the new password does not meet
            the complexity requirements or is too similar to the old
            password.
        """
        raise NotImplementedError()
        
    def exists(self, account_name):
        """
        Determines if the account exists.
        
        @param account_name: the account name
        @return: True if the account exists
        """
        raise NotImplementedError()
