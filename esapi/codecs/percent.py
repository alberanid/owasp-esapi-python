#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: Implementation of the Codec interface for percent encoding (aka URL
    encoding)
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

import esapi.codecs.codec as codec

class PercentCodec(codec.Codec):
    """
    Implementation of the Codec interface for percent encoding (aka URL
    encoding).
    """
    
    def __init__(self):
        codec.Codec.__init__(self)
    
    def encode_character(self, immune, char):
        """
        Encodes a single character according to the spec at 
        U{W3.org<http://www.w3.org/TR/html401/interact/forms.html#h-17.13.4.1>}.
        Spaces are replaced by '+'. All characters not in immune are escaped
        as described in U{this document<http://tools.ietf.org/html/rfc3986#section-2.1>}.
        """
        # check for immunes
        if char in immune:
            return char
            
        if char == ' ':
            return '+'
        
        ord_char = ord(char)
        
        # Only look at 8-bit 
        if not codec.is_8bit(ord_char):
            return char
        
        # Pass alphanumerics
        if char.isalnum():  
            return char
            
        hex_str = codec.get_hex_for_char(ord_char).upper()
        if ord_char < 0x10:
            hex_str = '0' + hex_str
            
        return '%' + hex_str
    
    def decode_character(self, pbs):
        """
        Decodes a single character according to the spec at:
        U{W3.org<http://www.w3.org/TR/html401/interact/forms.html#h-17.13.4.1>}.
        '+' decodes to ' '. All characters not in immune are escaped
        as described in U{this document<http://tools.ietf.org/html/rfc3986#section-2.1>}.
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
            except ValueError:
                pass
                # Malformed?
        
        pbs.reset()
        return None
        
