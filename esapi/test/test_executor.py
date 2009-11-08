#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: Test suite for Executor interface.
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
import os.path

from esapi.core import ESAPI
from esapi.codecs.windows import WindowsCodec
from esapi.codecs.unix import UnixCodec
from esapi.exceptions import ExecutorException

class ExecutorTest(unittest.TestCase):

    def __init__(self, test_name=""):
        """        
        @param test_name: the test name
        """
        unittest.TestCase.__init__(self, test_name)
             
    def test_execute_on_windows(self):
        if os.name != 'nt':
            print "Not executing test_execute_on_windows because os.name != 'nt'"
            return
            
        codec = WindowsCodec()
        instance = ESAPI.executor()
        orig_executable = "C:\\Windows\System32\cmd.exe"
        parent_dir = 'C:\\'
        params = ['/C', 'dir']
        result = instance.execute_system_command(orig_executable, params, parent_dir, codec=codec)
        print "result:", result
        
        executable = orig_executable + ";inject.exe"
        self.assertRaises(ExecutorException, instance.execute_system_command, executable, params, parent_dir, codec=codec)
        
        executable = orig_executable + "\\..\\cmd.exe"
        self.assertRaises(ExecutorException, instance.execute_system_command, executable, params, parent_dir, codec=codec)
        
        work_dir = "C:\\ridiculous"
        self.assertRaises(ExecutorException, instance.execute_system_command, orig_executable, params, parent_dir, work_dir, codec=codec)
        
        params.append("&dir")
        result = instance.execute_system_command(orig_executable, params, parent_dir, codec=codec)
        print "result:", result
        
        params = params[:-1] + ['c:\\autoexec.bat']
        result = instance.execute_system_command(orig_executable, params, parent_dir, codec=codec)
        print "result:", result
        
        params = params[:-1] + ['c:\\autoexec.bat c:\\config.sys']
        result = instance.execute_system_command(orig_executable, params, parent_dir, codec=codec)
        print "result:", result        
        
    def test_execute_on_linux(self):
        if os.name == 'nt':
            print "Not executing test_execute_on_linux because os.name == 'nt'"
            return
            
        codec = UnixCodec()
        instance = ESAPI.executor()
        executable = "/bin/sh"
        params = ['-c', 'ls', '/']
        parent_dir = '/'
        result = instance.execute_system_command(executable, params, parent_dir, codec=codec)
        print "result:", result

        # Don't log the params
        result = instance.execute_system_command(executable, params, parent_dir, log_params=False)

        # Test default codec
        result = instance.execute_system_command(executable, params, parent_dir)
        print "result:", result
        
        # Test bad executable
        self.assertRaises( ExecutorException, instance.execute_system_command, "/usr/bin/passwd", [], parent_dir)
        
        # Test bad working directory
        self.assertRaises( ExecutorException, instance.execute_system_command, executable, params, parent_dir, "/rediculous")
        
        executable = '/bin/sh;.inject'
        self.assertRaises( ExecutorException, instance.execute_system_command, executable, params, parent_dir, codec=codec)
        
        executable = '/../bin/sh'
        self.assertRaises( ExecutorException, instance.execute_system_command, executable, params, parent_dir, codec=codec)        

        executable = '/bin/sh'
        params.append(';ls')
        result = instance.execute_system_command(executable, params, parent_dir, codec=codec)
        print "result:", result    
        
        # Exceed the runtime
        executable = '/bin/sleep'
        params = ['30']
        self.assertRaises( ExecutorException, instance.execute_system_command, executable, params, parent_dir)
                
if __name__ == "__main__":
    unittest.main()

