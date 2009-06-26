#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
OWASP Enterprise Security API (ESAPI)
 
This file is part of the Open Web Application Security Project (OWASP)
Enterprise Security API (ESAPI) project. For details, please see
<a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
Copyright (c) 2009 - The OWASP Foundation

The ESAPI is published by OWASP under the BSD license. You should read and 
accept the LICENSE before you use, modify, and/or redistribute this software.

@author Craig Younkins (craig.younkins@owasp.org)
"""

import esapi.codecs.codec
from esapi.codecs.codec import Codec

class WindowsCodec(Codec):
    """
    Implementation of the Codec interface for '^' encoding from Windows
    command shell.
    """
   
    def __init__(self):
        """
        Instantiates the Windows codec.
        """
        Codec.__init__(self)
    
    def encode_character(self, immune, char):
        """
        Returns caret-encoded character
        """
        # Check for immunes
        if char in immune:
            return char
            
        # Check for alphanumeric characters
        hex_str = esapi.codecs.codec.get_hex_for_non_alphanumeric(char)
        if hex_str is None:
            return char
            
        return "^" + char
    
    def decode_character(self, pbs):
        """
        Returns the decoded version of the character starting at index, or
        None if no decoding is possible.
        
        All formats are legal including upper and lower case
        ^c decodes to c
        """
        pbs.mark()
        
        first = pbs.next()
        if first is None:
            pbs.reset()
            return None
            
        # if this is not an encoded character, return None
        if first != "^":
            pbs.reset()
            return None
            
        second = pbs.next()
          
        return second
        