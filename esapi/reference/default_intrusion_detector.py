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
@summary: Reference implementation of the IntrusionDetector interface.
@author: Craig Younkins (craig.younkins@owasp.org)
"""

from datetime import datetime, timedelta

from esapi.core import ESAPI
from esapi.translation import _
from esapi.intrusion_detector import IntrusionDetector
from esapi.logger import Logger
from esapi.exceptions import IntrusionException

class DefaultIntrusionDetector(IntrusionDetector):
    """
    Reference implementation of the IntrusionDetector interface. This 
    implementation monitors EnterpriseSecurityExceptions to see if any user
    exceeds a configurable threshold in a configurable time period.
    For example, it can monitor to see if ...
    
        - A user exceeds 10 input validation issues in a 1 minute period
        - There are more than 3 authentication problems in a 10 second period
        - More complex monitorings, such as establishing a baseline of
          expected behavior and detecting deviations from the baseline.
          
    This implementation stores state in the user's session, so that it will be
    properly cleaned up when the session is terminated. State is not otherwise
    persisted, so attacks that span sessions will not be detectable.
    
    @author: Craig Younkins (craig.younkins@owasp.org)
    """
    
    def __init__(self):
        self.logger = ESAPI.logger("IntrusionDetector")
    
    def add_exception(self, exception):
        # Log the exception
        if hasattr(exception, 'get_log_message'):
            self.logger.warning( Logger.SECURITY_FAILURE,
                exception.get_log_message(),
                exception )
        else:
            self.logger.warning( Logger.SECURITY_FAILURE,
                exception.message,
                exception )
                
        if isinstance(exception, IntrusionException):
            return
                
        # Add the exception to the current user, which may trigger a
        # dector
        user = ESAPI.authenticator().current_user
        event_name = exception.__class__.__name__
        try:
            self.add_security_event(user, event_name)
        except IntrusionException, extra:
            quota = ESAPI.security_configuration().get_quota(event_name)
            for action in quota.actions:
                message = (_("User exceeded quota of %(count)s per %(interval)s seconds for event %(event_name)s. Taking actions %(actions)s") %
                    {'count' : quota.count,
                     'interval' : quota.interval,
                     'event_name' : event_name,
                     'actions' : quota.actions,})
                self.take_security_action(action, message)
        
    def add_event(self, event_name, log_message):
        self.logger.warning( Logger.SECURITY_FAILURE, 
            _("Security event %(name)s received: %(message)s") %
                {'name' : event_name,
                 'message' : log_message,} )
                 
        # Add the event to the current user, which may trigger a detector
        user = ESAPI.authenticator().current_user
        
        try:
            self.add_security_event(user, "event_" + event_name)
        except IntrusionException, extra:
            quota = ESAPI.security_configuration().get_quota("event_" + event_name)
            for action in quota.actions:
                message = (_("User exceeded quota of %(count)s per %(interval)s seconds for event %(event_name)s. Taking actions %(actions)s") %
                    {'count' : quota.count,
                     'interval' : quota.interval,
                     'event_name' : event_name,
                     'actions' : quota.actions,})
                self.take_security_action(action, message)
        
    def take_security_action(self, action, message):
        """
        Take a specified security action. In this implementation, acceptable
        actions are: log, disable, logout, and lock.
        
        @param action: the action to take. Ie "log", "disable", "logout"
        @param message: the message to log if the action is "log"
        """
        if action == "log":
            self.logger.fatal( Logger.SECURITY_FAILURE,
                _("INTRUSION - ") + message )
                
        user = ESAPI.authenticator().current_user
        if user.is_anonymous():
            return
        elif action == "disable":
            user.disable()
        elif action == "logout":
            user.logout()
        elif action == "lock":
            user.lock()
        
    def add_security_event(self, user, event_name):
        """
        Adds a security event to the user. These events are used to check
        that the user has not reached the security thresholds set in the
        SecurityConfiguration.
        
        @param user: the user tha caused the event
        @param event_name: the name of the event that occurred.
        """
        if user.is_anonymous():
            return
            
        threshold = ESAPI.security_configuration().get_quota(event_name)
        if threshold is not None:
            event = user.event_map.get(event_name)
            if event is None:
                event = self.Event(event_name)
                user.event_map[event_name] = event
                
            event.increment(threshold.count, threshold.interval)
            
    class Event:
        def __init__(self, key):
            self.key = key
            self.times = []
            
        def increment(self, count, interval):
            now = datetime.now()
            self.times.append(now)
            if len(self.times) > count:
                num_to_remove = len(self.times) - count
                self.times = self.times[num_to_remove:]
                
            if len(self.times) == count:
                first_event_time = self.times[0]
                if now - first_event_time < timedelta(seconds=interval):
                    raise IntrusionException(
                        _("Threshold exceeded"),
                        _("Exceeded threshold for %(key)s") %
                        {'key' : self.key} )
