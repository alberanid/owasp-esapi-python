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

class JavascriptCodec(Codec):
    """
    Implementation of the Codec interface for backslash encoding in JavaScript.
    """
    
    def __init__(self):
        Codec.__init__(self)
        pass
        
    def encode_character(self, immune, char):
        """
        Returns a backslash encoded numeric format. Does not use backslash
        character escapes as these can be used in attacks.
        """
        if char in immune:
            return char
            
        hex_str = esapi.codecs.codec.get_hex_for_non_alphanumeric(char)
        if hex_str is None:
            return char
            
        # encode up to 256 with \\xHH
        temp = hex(ord(char))[2:].upper()
        if ord(char) < 256:
            padding = '00'[len(temp):]
            return "\\x" + padding + temp
           
        # otherwise encode with \\uHHHH
        padding = '0000'[len(temp):]
        return "\\u" + padding + temp
        
    def decode_character(self, pbs):
        pbs.mark()
        
        first = pbs.next()
        if first is None:
            pbs.reset()
            return None
            
        # if this is not an encoded character, return None
        if first != '\\':
            pbs.reset()
            return None
            
        second = pbs.next()
        if second is None:
            pbs.reset()
            return None
            
        char_to_values = {
            'b' : unichr(0x08),
            't' : unichr(0x09),
            'n' : unichr(0x0a),
            'v' : unichr(0x0b),
            'f' : unichr(0x0c),
            'r' : unichr(0x0d),
            '\"' : unichr(0x22),
            '\'' : unichr(0x27),
            '\\' : unichr(0x5c),
            }
            
        if char_to_values.has_key(second):
            return char_to_values[second]
            
        # look for \\xXX format
        if second.lower() == 'x':
            # Search for exactly 2 hex digits following
            buf = ''
            for i in range(2):
                char = pbs.next_hex()
                if char is not None: 
                    buf += char
                else:
                    pbs.reset()
                    return None
            try:
                # parse the hex digit and create a character
                i = int(buf, 16)
                return unichr(i)
            except ValueError:
                # throw exception for malformed entity?
                pbs.reset()
                return None
        
        # look for \\uXXXX format
        if second.lower() == 'u':
            # Search for exactly 4 hex digits following
            buf = ''
            for i in range(4):
                char = pbs.next_hex()
                if char is not None: 
                    buf += char
                else:
                    pbs.reset()
                    return None
            try:
                # parse the hex digit and create a character
                i = int(buf, 16)
                return unichr(i)
            except ValueError:
                # throw exception for malformed entity?
                pbs.reset()
                return None
                
        # look for one, two, or three octal digits
        if esapi.codecs.push_back_string.is_octal_digit(second):
            buf = ''
            # get digit 1
            buf += second
            
            # get digit 2 if present
            char2 = pbs.next()
            if not esapi.codecs.push_back_string.is_octal_digit(char2):
                pbs.pushback(char2)
            else:
                buf += char2
                # get digit 3 if present
                char3 = pbs.next()
                if not esapi.codecs.push_back_string.is_octal_digit(char3):
                    pbs.pushback(char3)
                else:
                    buf += char3
            try:
                # parse the octal string and create a character
                i = int(buf, 8)
                return unichr(i)
            except ValueError:
                # throw exception for malformed entity?
                pbs.reset()
                return None
                
        # ignore the backslash and return the character
        return second
        