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

from esapi.core import ESAPI
from esapi.translation import _
from esapi.executor import Executor
from esapi.codecs.windows import WindowsCodec
from esapi.codecs.unix import UnixCodec
from esapi.exceptions import ExecutorException

class DefaultExecutor(Executor):
    """

    
    @author: Craig Younkins (craig.younkins@owasp.org)
    """
    def __init__(self):
        self.logger = ESAPI.logger("Executor")
        if os.name == 'nt':
            self.logger.warning( Logger.SECURITY_SUCCESS,
                _("Using WindowsCodec for Executor. If this is not running on Windows, this could allow for injection") )
            self.codec = WindowsCodec()
        else:
            self.logger.warning( Logger.SECURITY_SUCCESS,
                _("Using UnixCodec for Executor. If this is not running on Unix, this could allow injection") )
            self.codec = UnixCodec()
        
    def execute_system_command(executable, 
            params, 
            work_dir=None,
            codec=None, 
            log_params=None):
            
        try:
            # Executable must exist
            if not os.path.exists(executable):
                raise ExecutorException(
                    _("Execution failure"),
                    _("No such executable: %s") % executable )
            
            # executable must 