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
@summary: The IntrusionDetector interface is intended to track security 
    relevant events and identify attack behavior.
@author: Craig Younkins (craig.younkins@owasp.org)
"""

from esapi.core import ESAPI
from esapi.translation import _

class IntrusionDetector(object):
    """
    The IntrusionDetector interface is intended to track security relevant
    events and identify attack behavior. The implementation can use as much
    state as necessary to detect attacks, but note that storing too much state
    will burden your system.
    
    The interface is currently designed to accept exceptions as well as custom
    events. Implementations can use this stream of information to detect both
    normal and abnormal behavior.
    
    @author: Craig Younkins (craig.younkins@owasp.org)
    """
    
    def add_exception(self, exception):
        """
        Adds the exception to the IntrusionDetector.
        
        The implementation should store the exception somewhere for the 
        current user in order to check if the user has reached the threshold
        for any type of security exception. The user object is the recommended
        place for storing these exceptions. If the user has reached any
        security thresholds, an appropriate security action, such as locking
        the user account, can be taken and logged.
        
        @param exception: the exception thrown
        @raises IntrusionException: Indicates an intrusion
        """
        raise NotImplementedError()
        
    def add_event(self, event_name, log_message):
        """
        Adds the event to the IntrusionDetector.
        
        The implementation should store the exception somewhere for the 
        current user in order to check if the user has reached the threshold
        for any type of security exception. The user object is the recommended
        place for storing these exceptions. If the user has reached any
        security thresholds, an appropriate security action, such as locking
        the user account, can be taken and logged.
        
        @param event_name: the event to add
        @param log_message: the message to log with the event
        @raises IntrusionException: Indicates an intrusion
        """
        raise NotImplementedError()
        
        
