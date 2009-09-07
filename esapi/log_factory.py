#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: The LogFactory interface is intended to allow substitution of various 
    logging packages, while providing a common interface to access them.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

# Todo

class LogFactory:
    """
    The LogFactory interface is intended to allow substitution of various 
    logging packages, while providing a common interface to access them.
    
    In the reference implementation, PythonLogFactory.py implements this 
    interface.  PythonLogFactory.py also contains an inner class called 
    PythonLogger which implements Logger.java and uses the Python logging 
    package to log events.
    
    @author: Craig Younkins (craig.younkins@owasp.org)
    
    """
    
    def __init__(self):
        pass

    def get_logger(self, key):
        """
        Gets the logger associated with the specified module or class name. 
        The module or class name is used by the logger to log which module or 
        class is generating the log events. The implementation of this method 
        should return any preexisting Logger associated with this module name, 
        rather than creating a new Logger.
        
        The PythonLogFactory reference implementation meets these requirements.
        
        @param key: The name of the class or module requesting the logger.
        @return: The Logger associated with this module.
        """
        raise NotImplementedError()
    
    def set_application_name(self, application_name):
        """
        This is needed to allow for null argument construction of log factories.
        
        @param application_name: A unique name to identify the application being logged.
        """
        raise NotImplementedError()
