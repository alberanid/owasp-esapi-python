#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@copyright: Copyright (c) 2009 - The OWASP Foundation
@summary: The AccessController interface defines a set of methods that can be
    used in a wide variety of applications to enforce access control.
@author: Craig Younkins (craig.younkins@owasp.org)
"""

from esapi.core import ESAPI
from esapi.translation import _

class AccessController():
    """
    The AccessController interface defines a set of methods that can be used in
    a wide variety of applications to enforce access control. In most 
    applications, access control must be performed in multiple different
    locations across the various application layers. This class provides
    access control for URLs, business functions, data, services, and files.
    
    The implementation of this interface will need to access the current User
    object (from Authenticator.current_user) to determine roles or permissions.
    In addition, the implementation will also need information about the 
    resources that are being accessed. Using the user information and the
    resource information, the implementation should return an access control
    decision.
    
    Implementors are encouraged to implement the ESAPI access control rules,
    like assert_authorized() using existing access control mechanisms, such as 
    is_user_in_role() or has_privilege(). While powerful, methods like
    is_user_in_role() can be confusing for developers, as users may be in
    multiple roles or possess multiple overlapping privileges. Direct use of
    these finer grained access control methods encourages the use of complex
    boolean tests throughout the code, which can easily lead to developer
    mistakes.
    
    The point of the ESAPI access control interface is to centralize access
    control logic behind easy to use calls like assert_authorized_for_data() so
    that access control is easy to use and easy to verify. Here is an example 
    of a very straightforward to implement, understand, and verify ESAPI access
    control check:
    
    try:
        ESAPI.access_controller().assert_authorized_for_function(
            "businessFunction" )
        # execute businessFunction
    except AccessControlException, extra:
        # attack in progress
        
    Note that in the user interface layer, acccess control checks can be used
    to control whether particular controls are rendered or not. These checks
    are supposed to fail when an unauthorized user is logged in, and do not
    represent attacks. Remember that regardless of how the user interface
    appears, an attacker can attempt to invoke any business function or access
    any data in your application. Therefore, access control checks in the user
    interface should be repeated in both the business logic and data layers.
    """
    
    def is_authorized_for_url(self, url):
        """
        Checks if the account is authorized to access the referenced URL.
        Generally, this method should be invoked in the application's
        controller or a filter as follows:
        
        ESAPI.access_controller().is_authorized_for_url(request.url)
        
        The implementation of this method should call 
        assert_authorized_for_url(url), and if an AccessControlException is not
        raised, this method should return true. This way, if the user is not
        authorized, false would be returned, and the exception would be logged.
        
        @param url: the url that the user should be checked for
        @return: true, if the user is authorized for the url
        """
        raise NotImplementedError()
        
    def is_authorized_for_function(self, function_name):
        """
        Checks if the account is authorized to access the referenced function.
        
        The implementation of this method should call
        assert_authorized_for_function(function_name), and if an 
        AccessControlException is not thrown, this method should return true.
        
        @param function_name: the name of the function
        @return: true, if the user is authorized for the function
        """
        raise NotImplementedError()
        
    def is_authorized_for_data(self, key):
        """
        Checks if an account is authorized to access the data, referenced by a 
        key as a string.
        
        The implementation of this method should call
        assert_authorized_for_data(key), and if an 
        AccessControlException is not thrown, this method should return true.
        
        @param key: a string key identifying the referenced data
        @return: true, if the user is authorized for the data
        """
        raise NotImplementedError()
        
    def is_authorized_for_file(self, filepath):
        """
        Checks if an account is authorized to access the referenced file.
        
        The implementation of this method should call
        assert_authorized_for_file(filepath), and if an AccessControlException
        is not raised, this method should return true.
        
        @param filepath: the path of the file to be checked, including filename
        @return: true, if the user is authorized for the file
        """
        raise NotImplementedError()
        
    def is_authorized_for_service(self, service_name):
        """
        Checks if an account is authorized to access the referenced service.
        This can be used in applications that provide access to a variety of
        back end services.
        
        The implementations of this method should call
        assert_authorized_for_service(service_name), and if an
        AccessControlException is not thrown, this method should return true.
        
        @param service_name: the name of the service
        @return: true, if the user is authorized for the service
        """
        raise NotImplementedError()
        
    def assert_authorized_for_url(self, url):
        """
        Checks if an account is authorized to access the referenced URL.
        
        Generally, this method should be invoked in the application's
        controller or in a filter as follows:
        
        ESAPI.access_controller().assert_authorized_for_url(request.url)
        
        This method raises an AccessControlException if access is not 
        authorized, or if the referenced URL does not exist. If the user is 
        authorized, this method simply returns.
        
        The implementation should do the following:
            - Check to see if the resource exists and if not, raise an
              AccessControlException
            - Use available information to make an access control decision
                - Ideally, this policy would be data driven
                - You can use the current user, roles, data type, data name,
                  time of day, etc.
                - Access control decisions must default to deny
            - If access is not permitted, raise an AccessControlException with
              details.
              
        @param url: the full url that the user is trying to access
        @raises AccessControlException: if access is not permitted.
        """
        raise NotImplementedError()
        
    def assert_authorized_for_function(self, function_name):
        """
        Checks if an account is authorized to access the referenced function.
        The implementation should define the function "namespace" to be
        enforced. Choosing something simple like the class name of action
        classes or menu item names will make this implementation easier to use.
        
        This method raises an AccessControlException if access is not
        authorized, or if the referenced function does not exist. If the user
        is authorized, this method simply returns.
        
        The implementation should do the following:
            - Check to see if the function exists and if not, raise an
              AccessControlException
            - Use available information to make an access control decision
                - Ideally, this policy would be data driven
                - You can use the current user, roles, data type, data name,
                  time of day, etc.
                - Access control decisions must default to deny
            - If access is not permitted, raise an AccessControlException with
              details.
              
        @param function_name: the name of the function
        @raises AccessControlException: if access is not permitted.
        """
        raise NotImplementedError()
        
    def assert_authorized_for_data(self, key):
        """
        Checks if the current user is authorized to access the referenced
        data. This method simply returns if access is authorized. It raises
        an AccessControlException if access is not authorized, or if the
        referenced data does not exist.
        
        The implementation should do the following:
            - Check to see if the data exists and if not, raise an
              AccessControlException
            - Use available information to make an access control decision
                - Ideally, this policy would be data driven
                - You can use the current user, roles, data type, data name,
                  time of day, etc.
                - Access control decisions must default to deny
            - If access is not permitted, raise an AccessControlException with
              details.
              
        @param key: the name for the data
        @raises AccessControlException: if access is not permitted.
        """
        raise NotImplementedError()
        
    def assert_authorized_for_file(self, filepath):
        """
        Checks if an account is authorized to access the referenced file.
        The implementation should validate and canonicalize thte input to make
        sure the filepath is not malicious.
        
        This method raises an AccessControlException if access is not 
        authorized, or if the referenced file does not exist. If the user is
        authorized, this method simply returns.
        
        The implementation should do the following:
            - Check to see if the file exists and if not, raise an
              AccessControlException
            - Use available information to make an access control decision
                - Ideally, this policy would be data driven
                - You can use the current user, roles, data type, data name,
                  time of day, etc.
                - Access control decisions must default to deny
            - If access is not permitted, raise an AccessControlException with
              details.
              
        @param filepath: path to the file to be checked.
        @raises AccessControlException: if access is not permitted.
        """
        raise NotImplementedError()
    
    def assert_authorized_for_service(self, service_name):
        """
        Checks if an account is authorized to access the referenced service.
        This can be used in applications that provide access to a variety of 
        backend services.
        
        This method raises an AccessControlException if access is not 
        authorized, or if the referenced service does not exist. If the user is
        authorized, this method simply returns.
        
        The implementation should do the following:
            - Check to see if the service exists and if not, raise an
              AccessControlException
            - Use available information to make an access control decision
                - Ideally, this policy would be data driven
                - You can use the current user, roles, data type, data name,
                  time of day, etc.
                - Access control decisions must default to deny
            - If access is not permitted, raise an AccessControlException with
              details.
              
        @param service_name: the service name
        @raises AccessControlException: if access is not permitted.
        """
        raise NotImplementedError()
 