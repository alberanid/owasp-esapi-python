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

class PercentCodec(Codec):
    """
    Implementation of the Codec interface for percent encoding (aka URL
    encoding)
    """
    
    def encode_character(self, immune, char):
        """
        Encodes a single character according to the spec at:
        http://www.w3.org/TR/html401/interact/forms.html#h-17.13.4.1
        Spaces are replaced by '+'. All characters not in immune are escaped
        as described in http://tools.ietf.org/html/rfc3986#section-2.1 .
        """
        
        if char in immune:
            return char
            
        if char == ' ':
            return '+'
        
        hex_str = esapi.codecs.codec.get_hex_for_non_alphanumeric(char)
        if hex_str is None:
            return char
            
        if ord(char) < 0x10:
            hex_str = '0' + hex_str
            
        return '%' + hex_str
    
    def decode_character(self, pbs):
        """
        Decodes a single character according to the spec at:
        http://www.w3.org/TR/html401/interact/forms.html#h-17.13.4.1
        '+' decodes to ' '. All characters not in immune are escaped
        as described in http://tools.ietf.org/html/rfc3986#section-2.1 .
        """
        pbs.mark()
        
        first = pbs.next()
        if first is None:
            pbs.reset()
            return None
           
        if first == '+':
            return ' '
            
        if first != '%':
            pbs.reset()
            return None
            
        hex_digits = ''
        for i in range(2):
            char = pbs.next_hex()
            if char is not None: 
                hex_digits += char
            
        if len(hex_digits) == 2:
            try:
                ret = unichr( int( hex_digits, 16 ) )
                return ret
            # Should never hit exception because cannot have int > 255
            # with only 2 hex digits. 0xFF = 255
            except ValueError:
                pass
                # Malformed?
        
        pbs.reset()
        return None
        