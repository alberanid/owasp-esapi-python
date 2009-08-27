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
@summary: The Executor interface is used to run an OS command with reduced
    security risk.
@author: Craig Younkins (craig.younkins@owasp.org)
"""

from esapi.core import ESAPI
from esapi.translation import _

class Executor():
    """
    The Executor interface is used to run an OS command with reduced security
    risk.
    
    Implementations should do as much as possible to minimize the risk of
    injection into either the command or parameters. In addition, 
    implementations should timeout after a specified time period in order to
    help prevent denial of service attacks.
    
    The class should perform lagging and error handling as well. Finally,
    implementations should handle errors and generate an ExecutorException
    with all the necessary information.
    
    @author: Craig Younkins (craig.younkins@owasp.org)
    """
    def __init__(self):
        pass
        
    def execute_system_command(executable, 
            params, 
            work_dir=None,
            codec=None, 
            log_params=None):
        """
        First this method checks that the executable exists. 
        
        If work_dir is given, the current working directory is changed to it.
        
        If codec is given, params are escaped using codec. If it is not given,
        params are escaped using the default OS codec.
        
        The call is logged. If log_params is True, the parameters are logged
        too.
        
        The executable is then invoked with the given params. Spawning the
        process should not block. The process is then allowed to execute
        until a maximum timeout has been reached. If the process is still
        executing when the timeout is reached, the process should be killed.
        
        @param executable: the command to execute
        @param params: the list of parameters to pass to the command
        @param work_dir: the directory the command should be executed from
        @param codec: the codec to escape the params
        @param log_params: if true, parameters will be logged.
        
        @raises ExecutorException: 
        @return: the output of the command being run
        """
        raise NotImplementedError()
        