#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: Implementation of the Codec interface for backslash encoding from 
    Unix command shell.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

import esapi.codecs.codec as codec

class UnixCodec(codec.Codec):
    """
    Implementation of the Codec interface for backslash encoding from Unix 
    command shell.
    """
   
    def __init__(self):
        """
        Instantiates the Unix codec.
        """
        codec.Codec.__init__(self)
    
    def encode_character(self, immune, char):
        """
        Returns backslash-encoded character
        """
        # Check for immune
        if char in immune:
            return char
            
        ord_char = ord(char)
            
        # Only look at 8-bit 
        if not codec.is_8bit(ord_char):
            return char
        
        # Pass alphanumerics
        if char.isalnum():  
            return char
            
        return "\\" + char
    
    def decode_character(self, pbs):
        """
        Returns the decoded version of the character starting at index, or
        None if no decoding is possible.
        
        All formats are legal including upper and lower case
        \c decodes to c
        """
        pbs.mark()
        
        first = pbs.next()
        if first is None:
            pbs.reset()
            return None
            
        # if this is not an encoded character, return None
        if first != "\\":
            pbs.reset()
            return None
            
        second = pbs.next()
        if second is None:
            pbs.reset()
            return None
            
        return second
        
