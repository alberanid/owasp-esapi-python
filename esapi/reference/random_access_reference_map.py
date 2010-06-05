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
@summary: 
@author: Craig Younkins (craig.younkins@owasp.org)
"""

from esapi.core import ESAPI
from esapi.translation import _
from esapi.encoder import Encoder
from esapi.exceptions import AccessControlException
from esapi.access_reference_map import AccessReferenceMap

class RandomAccessReferenceMap(AccessReferenceMap):
    """
    Reference implementation of the AccessReferenceMap interface. This
    implementation generates random 6 character alphanumeric strings for
    indirect references.
    
    @author: Craig Younkins (craig.younkins@owasp.org)
    """
    INDIRECT_LENGTH = 6
    
    def __init__(self, initial=None):
        # Indirect to direct
        self.itod = {}
        
        # Direct to indirect
        self.dtoi = {}
        
        if initial is not None:
            self.update(initial)
        
    def get_indirect_reference(self, direct):
        return self.dtoi.get(direct)
        
    def get_direct_reference(self, indirect):
        if self.itod.has_key(indirect):
            return self.itod[indirect]
        
        raise AccessControlException(
            _("Access denied"),
            _("Request for invalid indirect reference: %(ref)s") %
            {'ref' : indirect} )
        
    def add_direct_reference(self, direct):
        if self.dtoi.has_key(direct):
            return self.dtoi[direct]
            
        indirect = self.get_unique_random_reference()
        self.itod[indirect] = direct
        self.dtoi[direct] = indirect
        return indirect
        
    def get_unique_random_reference(self, invalid=None):
        candidate = None
        if invalid is None:
            invalid = ()
            
        while ( candidate is None or 
                self.itod.has_key(candidate) or
                candidate in invalid ):
            candidate = ESAPI.randomizer().get_random_string(
                self.INDIRECT_LENGTH, Encoder.CHAR_ALPHANUMERICS)
            
        return candidate
        
    def remove_direct_reference(self, direct):
        indirect = self.dtoi.get(direct)
        if indirect is not None:
            del self.itod[indirect]
            del self.dtoi[direct]
        
        return indirect
        
    def update(self, set):
        dtoi_old = self.dtoi.copy()
        itod_old = self.itod.copy()
        
        self.dtoi.clear()
        self.itod.clear()
        
        for direct in set:
            if dtoi_old.has_key(direct):
                indirect = dtoi_old[direct]
            else:
                indirect = self.get_unique_random_reference(itod_old.keys())
            
            self.itod[indirect] = direct
            self.dtoi[direct] = indirect
            
    def indirects(self):
        for indirect in self.itod.keys():
            yield indirect
            
            
