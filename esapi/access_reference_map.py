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
@summary: The AccessReferenceMap interface is used to map from a set of internal
    direct object references to a set of indirect references that are safe
    to disclose publicly.
@author: Craig Younkins (craig.younkins@owasp.org)
"""

from esapi.core import ESAPI
from esapi.translation import _

class AccessReferenceMap(object):
    """
    The AccessReferenceMap interface is used to map from a set of internal
    direct object references to a set of indirect references that are safe
    to disclose publicly. This can be used to help protect database keys,
    filenames, and other types of direct object references. As a rule,
    developers should not expose their direct object references as it enables
    attackers to attempt to manipulate them.
    
    Indirect references are handled as strings to facilitate their use in HTML.
    Implementations can generate simple integers or more complicated random
    character strings as indirect references. Implementations should probably
    add a constructor that takes a list of direct references.
    
    Note that in addition to defeating all forms of parameter tampering
    attacks, there is a side benefit of the AccessReferenceMap. Using random
    strings as indirect object references, as opposed to simple integers,
    makes it impossible for attacker to guess valid identifiers. So if
    per-user AccessReferenceMaps are used, then request forgery (CSRF)
    attacks will also be prevented.
    
    @author: Craig Younkins (craig.younkins@owasp.org)
    """
    def __init__(self):
        pass
        
    def get_indirect_reference(self, direct_ref):
        """
        Get a safe indirect reference to use in place of a potentially
        sensitive direct object reference. Developers should use this call
        when building URLs, form fields, hidden fields, etc... to help protect
        their private implementation information.
        
        @param direct_ref: the direct object you want to reference
        @return: the indirect reference
        """
        raise NotImplementedError()
        
    def get_direct_reference(self, indirect_ref):
        """
        Get the original direct object reference from an indirect reference.
        Developers should use this when they get an indirect reference from a
        request to translate it back into the real direct reference. If an
        invalid indirect reference is requested, then an
        AccessControlException is raised.
        
        @param indirect_ref: the indirect object reference
        @return: the direct reference
        @raises AccessControlException: If no direct reference exists for the
            specified indirect reference
        """
        raise NotImplementedError()
        
    def add_direct_reference(self, direct_ref):
        """
        Adds a direct reference to the AccessReferenceMap, then generates
        and returns an associated indirect reference.
        
        @param direct_ref: the direct reference
        @return: the corresponding indirect reference
        """
        raise NotImplementedError()
        
    def remove_direct_reference(self, direct_ref):
        """
        Removes a direct reference and its associated indirect reference from
        the AccessReferenceMap.
        
        @param direct_ref: the direct reference to remove
        @return: the corresponding indirect reference
        """
        raise NotImplementedError()
        
    def update(self, set):
        """
        Updates the AccessReferenceMap with a new set of direct references,
        maintaining any existing indirect references associated with items
        that are in the new list.
        New indirect references could be generated every time, but that might
        mess up anything that previously used an indirect reference, such as
        a URL parameter.
        
        @param set: An iterable of direct references.
        """
        raise NotImplementedError()
