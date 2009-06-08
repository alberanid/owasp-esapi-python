"""
OWASP Enterprise Security API (ESAPI)
 
This file is part of the Open Web Application Security Project (OWASP)
Enterprise Security API (ESAPI) project. For details, please see
<a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
Copyright (c) 2009 - The OWASP Foundation

The ESAPI is published by OWASP under the BSD license. You should read and accept the
LICENSE before you use, modify, and/or redistribute this software.

@author Craig Younkins (craig.younkins@owasp.org)
@created 2009
"""

# Todo

class LogFactory:
    """
    The LogFactory interface is intended to allow substitution of various logging packages, while providing
    a common interface to access them.
    
    In the reference implementation, PythonLogFactory.py implements this interface.  PythonLogFactory.py also contains an
    inner class called PythonLogger which implements Logger.java and uses the Python logging package to log events.
    
    @see esapi.ESAPI
    
    @author Craig Younkins (craig.younkins@owasp.org)
    
    """

    def getLogger(self, classOrMod):
        """
        Gets the logger associated with the specified module or class name. The module or class name is used by the logger to log which
        module or class is generating the log events. The implementation of this method should return any preexisting Logger
        associated with this module name, rather than creating a new Logger.
        <br><br>
        The PythonLogFactory reference implementation meets these requirements.
        
        @param classOrMod
                    The name of the class or module requesting the logger.
        @return
                    The Logger associated with this module.
        """
        raise NotImplementedError()
    
    def setApplicationName(self, applicationName):
        """
        This is needed to allow for null argument construction of log factories.
        
        @param applicationName
                    A unique name to identify the application being logged.
        """
        raise NotImplementedError()