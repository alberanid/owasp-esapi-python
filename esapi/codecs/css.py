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
import esapi.codecs.push_back_string

class CSSCodec(Codec):
    """
    Implementation of the Codec interface for backslash encoding used in CSS.
    """
   
    def __init__(self):
        Codec.__init__(self)

    
    def encode_character(self, immune, char):
        """
        Encodes a character using CSS backslash style.
        """
        if char in immune:
            return char
            
        hex_str = esapi.codecs.codec.get_hex_for_non_alphanumeric(char)
        if hex_str is None:
            return char
            
        # Return the hex and end in whitespace to terminate
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
        if esapi.codecs.push_back_string.is_hex_digit(second):
            # Search for up to 6 hex digits following until a space
            buf = ''
            buf += second
            for i in range(6):
                next_char = pbs.next()
                if next_char is None or ord(next_char) == 0x20:
                    break
                if esapi.codecs.push_back_string.is_hex_digit(next_char):
                    buf += next_char
                else:
                    pbs.pushback(next_char)
                    break
            try:
                i = int(buf, 16)
                return unichr(i)
            except ValueError:
                # Throw an exception for malformed entity?
                pass
                
        return second
        