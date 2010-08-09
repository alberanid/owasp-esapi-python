#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: Implementation of the codec.Codec interface for backslash encoding 
    used in CSS.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

import esapi.codecs.codec as codec
import esapi.codecs.push_back_string as push_back_string

class CSSCodec(codec.Codec):
    """
    Implementation of the codec.Codec interface for backslash encoding used in 
    CSS.
    """
   
    def __init__(self):
        codec.Codec.__init__(self)

    def encode_character(self, immune, char):
        """
        Encodes a character using CSS backslash style.
        """
        # Check for immunes
        if char in immune:
            return char
        
        ord_char = ord(char)
            
        # Only look at 8-bit 
        if not codec.is_8bit(ord_char):
            return char
        
        # Pass alphanumerics
        if char.isalnum():  
            return char
            
        # Return the hex and end in whitespace to terminate
        hex_str = codec.get_hex_for_char(ord_char)
        return "\\" + hex_str + " "
    
    def decode_character(self, pbs):
        """
        Returns the decoded version of the character starting at index, or 
        null if no decoding is possible. This implementation does not support 
        \\### octal encoding.

        Formats all are legal both upper/lower case: 
        \\x - special characters \\HHHH
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
            
        # look for \HHH format
        if push_back_string.is_hex_digit(second):
            # Search for up to 6 hex digits following until a space
            buf = ''
            buf += second
            for i in range(6):
                next_char = pbs.next()
                if next_char is None or ord(next_char) == 0x20:
                    break
                if push_back_string.is_hex_digit(next_char):
                    buf += next_char
                else:
                    pbs.reset()
                    return None
            try:
                i = int(buf, 16)
                return unichr(i)
            except ValueError:
                # Throw an exception for malformed entity?
                pass
                
        pbs.reset()
        return None
        
