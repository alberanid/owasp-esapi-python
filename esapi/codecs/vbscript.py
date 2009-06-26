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
from esapi.encoder import Encoder

class VBScriptCodec(Codec):
    """
    Implementation of the Codec interface for 'quote' encoding from VBScript.
    """
   
    def __init__(self):
        """
        Instantiates the VBScript codec.
        """
        Codec.__init__(self)
        
    def encode(self, immune, input_):
        """
        Encode a String so that it can be safely used in a specific context.
        
        @param immune characters immune to encoding
        @param input the string to encode
        @return the encoded string
        """
        buf = ''
        encoding = False
        inquotes = False
        
        for i in range(len(input_)):
            char = input_[i]
            # handle normal characters and surround them with quotes
            if char in Encoder.CHAR_ALPHANUMERICS or char in immune:
                if encoding and i > 0:
                    buf += "&"
                if not inquotes and i > 0:
                    buf += '"'
                buf += char
                inquotes = True
                encoding = False
                
            # handle characters than need encoding
            else:
                if inquotes:
                    buf += '"'
                if i > 0:
                    buf += "&"
                buf += self.encode_character(immune, char)
                inquotes = False
                encoding = True
                
        return buf
    
    def encode_character(self, immune, char):
        """
        Returns quote-encoded character
        """
        # Check for immunes
        if char in immune:
            return char
            
        # Check for alphanumeric characters
        hex_str = esapi.codecs.codec.get_hex_for_non_alphanumeric(char)
        if hex_str is None:
            return char
            
        return "chrw(" + str(ord(char)) + ")"
    
    def decode_character(self, pbs):
        """
        Returns the decoded version of the character starting at index, or
        None if no decoding is possible.
	  
        Formats all are legal both upper/lower case:
        "x - all special characters
	    chrw(x)
        """
        pbs.mark()
        
        first = pbs.next()
        if first is None:
            pbs.reset()
            return None
            
        # if this is not an encoded character, return None
        if first == '"':
            second = pbs.next()
            if second is None:
                pbs.reset()
                return None
                
            return second
        elif first == 'c':
            # could be chrw(x)
            next_4 = ''.join([pbs.next() for x in range(4)])
            if next_4 == 'hrw(':
                num_buf = ''
                for i in range(4):
                    # Look for a maximum of 4 digits afterwards
                    next_num = pbs.next()
                    if next_num is not None and next_num.isdigit():
                        num_buf += next_num
                    else:
                        pbs.pushback(next_num)
                        break
                if not pbs.peek(')'):
                    # Something isn't right here
                    pbs.reset()
                    return None
                # Eat the end paren
                pbs.next()
                # Try to convert to number
                try:
                    decoded = unichr(int(num_buf))
                    return decoded
                except ValueError:
                    pbs.reset()
                    return None
            else:
                # fall through to reset and return None
                pass
        
        pbs.reset()
        return None
        