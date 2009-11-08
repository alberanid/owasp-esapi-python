#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: Test suite for AccessController interface.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

# Use esapi/test/conf instead of esapi/conf
# It is important that this is at the top, as it affects the imports below
# by loading the test configuration instead of the normal one.
# This should ONLY ever be used in the unit tests.
import esapi.test.conf

import unittest
import os
from esapi.core import ESAPI
from esapi.exceptions import AccessControlException

class AccessControllerTest(unittest.TestCase):
    def __init__(self, test_name=""):
        unittest.TestCase.__init__(self, test_name)
        
    def setUp(self):
        auth = ESAPI.authenticator()
        auth.clear_all_data()
        password = "passwordForAC"
        
        # create user 'ACAlice' with 'user' role
        user = auth.get_user('ACAlice')
        if user is None:
            user = auth.create_user('ACAlice', password, password)
        user.add_role('user')
        
        # create user 'ACBob' with 'admin' role
        user = auth.get_user('ACBob')
        if user is None:
            user = auth.create_user('ACBob', password, password)
        user.add_role('admin')
        
        # create user 'ACMitch' with 'user' and 'admin' roles
        user = auth.get_user('ACMitch')
        if user is None:
            user = auth.create_user('ACMitch', password, password)
        user.add_role('user')
        user.add_role('admin')  
            
    def test_match_rule(self):
        self.assertFalse(ESAPI.access_controller().is_authorized_for_url('/nobody'))
             
    def test_is_authorized_for_url(self):
        instance = ESAPI.access_controller()
        auth = ESAPI.authenticator()
        
        auth.current_user = auth.get_user("ACAlice")
        self.assertFalse(instance.is_authorized_for_url("/nobody"))
        self.assertFalse(instance.is_authorized_for_url("/test/admin"))
        self.assertTrue(instance.is_authorized_for_url("/test/user"))
        self.assertTrue(instance.is_authorized_for_url("/test/all"))
        self.assertFalse(instance.is_authorized_for_url("/test/none"))
        self.assertTrue(instance.is_authorized_for_url("/test/none/test.gif"))
        self.assertFalse(instance.is_authorized_for_url("/test/none/test.exe"))
        self.assertTrue(instance.is_authorized_for_url("/test/none/test.png"))
        self.assertFalse(instance.is_authorized_for_url("/test/moderator"))
        self.assertTrue(instance.is_authorized_for_url("/test/profile"))
        self.assertFalse(instance.is_authorized_for_url("/upload"))

        auth.current_user = auth.get_user("ACBob")
        self.assertFalse(instance.is_authorized_for_url("/nobody"))
        self.assertTrue(instance.is_authorized_for_url("/test/admin"))
        self.assertFalse(instance.is_authorized_for_url("/test/user"))
        self.assertTrue(instance.is_authorized_for_url("/test/all"))
        self.assertFalse(instance.is_authorized_for_url("/test/none"))
        self.assertTrue(instance.is_authorized_for_url("/test/none/test.png"))
        self.assertFalse(instance.is_authorized_for_url("/test/moderator"))
        self.assertTrue(instance.is_authorized_for_url("/test/profile"))
        self.assertFalse(instance.is_authorized_for_url("/upload"))

        auth.current_user = auth.get_user("ACMitch")
        self.assertFalse(instance.is_authorized_for_url("/nobody"))
        self.assertTrue(instance.is_authorized_for_url("/test/admin"))
        self.assertTrue(instance.is_authorized_for_url("/test/user"))
        self.assertTrue(instance.is_authorized_for_url("/test/all"))
        self.assertFalse(instance.is_authorized_for_url("/test/none"))
        self.assertTrue(instance.is_authorized_for_url("/test/none/test.png"))
        self.assertFalse(instance.is_authorized_for_url("/test/moderator"))
        self.assertTrue(instance.is_authorized_for_url("/test/profile"))
        self.assertFalse(instance.is_authorized_for_url("/upload"))

        instance.assert_authorized_for_url( "/test/admin" )
        self.assertRaises(AccessControlException, instance.assert_authorized_for_url, "/nobody" )
        
    def test_is_authorized_for_function(self):
        instance = ESAPI.access_controller()
        auth = ESAPI.authenticator()

        auth.current_user = auth.get_user("ACAlice")
        self.assertTrue(instance.is_authorized_for_function("/FunctionA"))
        self.assertFalse(instance.is_authorized_for_function("/FunctionAdeny"))
        self.assertFalse(instance.is_authorized_for_function("/FunctionB"))
        self.assertFalse(instance.is_authorized_for_function("/FunctionBdeny"))
        self.assertTrue(instance.is_authorized_for_function("/FunctionC"))
        self.assertFalse(instance.is_authorized_for_function("/FunctionCdeny"))

        auth.current_user = auth.get_user("ACBob")
        self.assertFalse(instance.is_authorized_for_function("/FunctionA"))
        self.assertFalse(instance.is_authorized_for_function("/FunctionAdeny"))
        self.assertTrue(instance.is_authorized_for_function("/FunctionB"))
        self.assertFalse(instance.is_authorized_for_function("/FunctionBdeny"))
        self.assertTrue(instance.is_authorized_for_function("/FunctionD"))
        self.assertFalse(instance.is_authorized_for_function("/FunctionDdeny"))

        auth.current_user = auth.get_user("ACMitch") 
        self.assertTrue(instance.is_authorized_for_function("/FunctionA"))
        self.assertFalse(instance.is_authorized_for_function("/FunctionAdeny"))
        self.assertTrue(instance.is_authorized_for_function("/FunctionB"))
        self.assertFalse(instance.is_authorized_for_function("/FunctionBdeny"))
        self.assertTrue(instance.is_authorized_for_function("/FunctionC"))
        self.assertFalse(instance.is_authorized_for_function("/FunctionCdeny"))

        instance.assert_authorized_for_function("/FunctionA")
        self.assertRaises(AccessControlException, instance.assert_authorized_for_function, "/FunctionDdeny" )
		
    def test_is_authorized_for_data(self):
        instance = ESAPI.access_controller()
        auth = ESAPI.authenticator()

        adminR = "java.util.ArrayList"
        adminRW = "java.lang.Math"
        userW = "java.util.Date"
        userRW = "java.lang.String"
        anyR = "java.io.BufferedReader"
        userAdminR = "java.util.Random"
        userAdminRW = "java.awt.event.MouseWheelEvent"
        undefined = "java.io.FileWriter"

        # test User
        auth.current_user = auth.get_user("ACAlice")
        self.assertTrue(instance.is_authorized_for_data("read", userRW))
        self.assertFalse(instance.is_authorized_for_data("read", undefined))
        self.assertFalse(instance.is_authorized_for_data("write", undefined))
        self.assertFalse(instance.is_authorized_for_data("read", userW))
        self.assertFalse(instance.is_authorized_for_data("read", adminRW))
        self.assertTrue(instance.is_authorized_for_data("write", userRW))
        self.assertTrue(instance.is_authorized_for_data("write", userW))
        self.assertFalse(instance.is_authorized_for_data("write", anyR))
        self.assertTrue(instance.is_authorized_for_data("read", anyR))
        self.assertTrue(instance.is_authorized_for_data("read", userAdminR))
        self.assertTrue(instance.is_authorized_for_data("write", userAdminRW))

        # test Admin
        auth.current_user = auth.get_user("ACBob")
        self.assertTrue(instance.is_authorized_for_data("read", adminRW))
        self.assertFalse(instance.is_authorized_for_data("read", undefined))
        self.assertFalse(instance.is_authorized_for_data("write", undefined))
        self.assertFalse(instance.is_authorized_for_data("read", userRW))
        self.assertTrue(instance.is_authorized_for_data("write", adminRW))
        self.assertFalse(instance.is_authorized_for_data("write", anyR))
        self.assertTrue(instance.is_authorized_for_data("read", anyR))
        self.assertTrue(instance.is_authorized_for_data("read", userAdminR))
        self.assertTrue(instance.is_authorized_for_data("write", userAdminRW))

        # test User/Admin
        auth.current_user = auth.get_user("ACMitch")
        self.assertTrue(instance.is_authorized_for_data("read", userRW))
        self.assertFalse(instance.is_authorized_for_data("read", undefined))
        self.assertFalse(instance.is_authorized_for_data("write", undefined))
        self.assertFalse(instance.is_authorized_for_data("read", userW))
        self.assertTrue(instance.is_authorized_for_data("read", adminR))
        self.assertTrue(instance.is_authorized_for_data("write", userRW))
        self.assertTrue(instance.is_authorized_for_data("write", userW))
        self.assertFalse(instance.is_authorized_for_data("write", anyR))
        self.assertTrue(instance.is_authorized_for_data("read", anyR))
        self.assertTrue(instance.is_authorized_for_data("read", userAdminR))
        self.assertTrue(instance.is_authorized_for_data("write", userAdminRW))

        instance.assert_authorized_for_data("read", userRW)
        self.assertRaises(AccessControlException, instance.assert_authorized_for_data, "write", adminR )

    def test_is_authorized_for_file(self):
        instance = ESAPI.access_controller()
        auth = ESAPI.authenticator()

        auth.current_user = auth.get_user("ACAlice")
        self.assertTrue(instance.is_authorized_for_file("/Dir/File1"))
        self.assertFalse(instance.is_authorized_for_file("/Dir/File2"))
        self.assertTrue(instance.is_authorized_for_file("/Dir/File3"))
        self.assertFalse(instance.is_authorized_for_file("/Dir/ridiculous"))

        auth.current_user = auth.get_user("ACBob")
        self.assertFalse(instance.is_authorized_for_file("/Dir/File1"))
        self.assertTrue(instance.is_authorized_for_file("/Dir/File2"))
        self.assertTrue(instance.is_authorized_for_file("/Dir/File4"))
        self.assertFalse(instance.is_authorized_for_file("/Dir/ridiculous"))

        auth.current_user = auth.get_user("ACMitch")
        self.assertTrue(instance.is_authorized_for_file("/Dir/File1"))
        self.assertTrue(instance.is_authorized_for_file("/Dir/File2"))
        self.assertFalse(instance.is_authorized_for_file("/Dir/File5"))
        self.assertFalse(instance.is_authorized_for_file("/Dir/ridiculous"))

        instance.assert_authorized_for_file("/Dir/File1")
        self.assertRaises(AccessControlException, instance.assert_authorized_for_file, "/Dir/File6" )
    def test_is_authorized_for_service(self):
        instance = ESAPI.access_controller()
        auth = ESAPI.authenticator()

        auth.current_user = auth.get_user("ACAlice")
        self.assertTrue(instance.is_authorized_for_service("/services/ServiceA"))
        self.assertFalse(instance.is_authorized_for_service("/services/ServiceB"))
        self.assertTrue(instance.is_authorized_for_service("/services/ServiceC"))

        self.assertFalse(instance.is_authorized_for_service("/test/ridiculous"))

        auth.current_user = auth.get_user("ACBob")
        self.assertFalse(instance.is_authorized_for_service("/services/ServiceA"))
        self.assertTrue(instance.is_authorized_for_service("/services/ServiceB"))
        self.assertFalse(instance.is_authorized_for_service("/services/ServiceF"))
        self.assertFalse(instance.is_authorized_for_service("/test/ridiculous"))

        auth.current_user = auth.get_user("ACMitch")
        self.assertTrue(instance.is_authorized_for_service("/services/ServiceA"))
        self.assertTrue(instance.is_authorized_for_service("/services/ServiceB"))
        self.assertFalse(instance.is_authorized_for_service("/services/ServiceE"))
        self.assertFalse(instance.is_authorized_for_service("/test/ridiculous"))

        instance.assert_authorized_for_service("/services/ServiceD")
        self.assertRaises(AccessControlException, instance.assert_authorized_for_service, "/test/ridiculous" )
        
if __name__ == "__main__":
    unittest.main()
