#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: Test suite for AccessReferenceMap interface.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

# Use esapi/test/conf instead of esapi/conf
# It is important that this is at the top, as it affects the imports below
# by loading the test configuration instead of the normal one.
# This should ONLY ever be used in the unit tests.
import esapi.test.conf

import unittest

from esapi.core import ESAPI
from esapi.exceptions import AccessControlException

class ARMTest(unittest.TestCase):
    def __init__(self, test_name=""):
        unittest.TestCase.__init__(self, test_name)
        
    def get_new_arm(self, *args):
        klass = ESAPI.security_configuration().get_class_for_interface("access_reference_map")
        return klass(*args)
        
    def test_update(self):
        arm = self.get_new_arm()
        
        direct_refs = ('direct1', 'direct2', 'direct3')
        
        # test to make sure update does something
        arm.update(direct_refs)
        indirect_ref1 = arm.get_indirect_reference('direct1')
        if indirect_ref1 is None:
            self.fail()
        
        # makes sure update removes items that are no longer in the list
        direct_refs = ('direct1', 'direct4')
        arm.update(direct_refs)
        self.assertTrue(arm.get_indirect_reference('direct2') is None)
        
        # Make sure the indirect reference for direct1 didn't change
        new_indirect_ref1 = arm.get_indirect_reference('direct1')
        self.assertEquals(indirect_ref1, new_indirect_ref1)
        
    def test_indirect_references(self):
        direct_refs = ('123', '234', '345')
        arm = self.get_new_arm(direct_refs)
        indirect = arm.get_indirect_reference('234')
        
        # indirect reference should not be in direct references
        self.assertFalse(indirect in direct_refs)
        
        # Confirm we can get the data back
        self.assertEquals('234', arm.get_direct_reference(indirect))
        
    def test_invalid_indirect(self):
        # If the indirect reference is invalid, AccessControlException should
        # be raised
        direct_refs = ('123', '234', '345')
        arm = self.get_new_arm(direct_refs)
        self.assertRaises( AccessControlException, 
            arm.get_direct_reference, "invalid" )
            
    def test_add_direct_reference(self):
        direct_refs = ('123', '234', '345')
        arm = self.get_new_arm(direct_refs)
        
        new_direct = "newDirect"
        indirect1 = arm.add_direct_reference(new_direct)
        got_direct = arm.get_direct_reference(indirect1)
        self.assertEquals(new_direct, got_direct)
        
        # Indirect reference should not change
        indirect2 = arm.add_direct_reference(new_direct)
        self.assertEquals(indirect1, indirect2)
        
    def test_remove_direct_reference(self):
        direct_refs = ('123', '234', '345')
        arm = self.get_new_arm(direct_refs)
        
        my_direct = '234'
        indirect = arm.get_indirect_reference(my_direct)
        if indirect is None:
            self.fail()
        deleted_indirect = arm.remove_direct_reference(my_direct)
        self.assertEquals(indirect, deleted_indirect)
        
        # Ensure we can't access the data anymore
        self.assertRaises( AccessControlException, 
            arm.get_direct_reference, indirect )
            
        bogus = arm.remove_direct_reference("ridiculous")
        self.assertTrue(bogus is None)
        
if __name__ == "__main__":
    unittest.main()
