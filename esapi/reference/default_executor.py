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
@summary: The default implementation of the Executor interface.
@author: Craig Younkins (craig.younkins@owasp.org)
"""

import os
import os.path
import subprocess
from datetime import datetime, timedelta
import time

from esapi.core import ESAPI
from esapi.logger import Logger
from esapi.translation import _
from esapi.executor import Executor
from esapi.codecs.windows import WindowsCodec
from esapi.codecs.unix import UnixCodec
from esapi.exceptions import ExecutorException

class DefaultExecutor(Executor):
    """
    The reference implementation of the Executor interface. This implementation
    is very restrictive. Commands must match the canonical path and pass
    Validator.is_valid_directory_path and Validator.is_valid_filename.
    
    @author: Craig Younkins (craig.younkins@owasp.org)
    """
    def __init__(self):
        self.logger = ESAPI.logger("Executor")
        self.working_dir = ESAPI.security_configuration().get_working_directory()
        self.max_running_time = ESAPI.security_configuration().get_max_running_time()
        if os.name == 'nt':
            self.logger.warning( Logger.SECURITY_SUCCESS,
                _("Using WindowsCodec for Executor. If this is not running on Windows, this could allow for injection") )
            self.codec = WindowsCodec()
        else:
            self.logger.warning( Logger.SECURITY_SUCCESS,
                _("Using UnixCodec for Executor. If this is not running on Unix, this could allow injection") )
            self.codec = UnixCodec()
        
    def execute_system_command(
            self,
            executable, 
            params, 
            parent_dir,
            working_dir=None,
            codec=None, 
            log_params=True):
            
        if codec is None:
            codec = self.codec
            
        if working_dir is None:
            working_dir = self.working_dir
            
        try:
            # Executable must exist
            if not os.path.exists(executable):
                raise ExecutorException(
                    _("Execution failure"),
                    _("No such executable: %(executable)s") % 
                    {'executable' : executable} )
            
            directory, filename = os.path.split(executable)

            # executable must use canonical path
            if not ESAPI.validator().is_valid_directory_path(
                "Executor",
                directory,
                parent_dir,
                False):
                raise ExecutorException(
                    _("Execution failure"),
                    _("Directory did not pass validation: %(dir)s") %
                    { 'dir' : directory } )
                    
            # Must be in approved list
            approved = ESAPI.security_configuration().get_allowed_executables()
            if executable not in approved:
                raise ExecutorException(
                    _("Execution failure"),
                    _("Attempt to invoke executable that is not listed as an approved executable in configuration: %(executable)s") %
                    {'executable' : executable} )
                    
            # Escape parameters
            params = [ESAPI.encoder().encode_for_os(codec,param) for param in params]
            
            # Working directory must exist
            if not os.path.exists(working_dir):
                raise ExecutorException(
                    _("Execution failure"),
                    _("No such working directory for running executable: %(dir)s") %
                    {'dir' : working_dir} )
                    
            args = params
            args.insert(0, executable)
            start_time = datetime.now()
            proc = subprocess.Popen( args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=working_dir )
            
            if log_params:
                self.logger.warning( Logger.SECURITY_SUCCESS,
                    _("Initiating executable %(args)s in %(dir)s" ) %
                    {'args' : str(args),
                     'dir' : working_dir } )
            else:
                self.logger.warning( Logger.SECURITY_SUCCESS,
                    _("Initiating executable %(executable)s in %(dir)s" ) %
                    {'executable' : args[0],
                     'dir' : working_dir } )
                     
            while (proc.poll() is None and 
                   datetime.now() - start_time < self.max_running_time):
                time.sleep(1)
                
            if proc.poll() is None:
                # Kill the process because it ran too long
                proc.terminate()
                time.sleep(1)
                if proc.poll() is None:
                    proc.kill()
                raise ExecutorException(
                    _("Execution failure"),
                    _("Process exceeded maximum running time and was killed: %(executable)s") %
                    {'executable' : executable} )
                    
            else:
                # Process terminated in allotted timeframe
                stdout_and_err = proc.communicate()
                return stdout_and_err
        except Exception, extra:
            raise ExecutorException(
                _("Execution failure"),
                _("Exception thrown during execution of system command"),
                extra )
                
