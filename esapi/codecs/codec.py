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

from esapi.codecs.push_back_string import PushbackString

def get_hex_for_non_alphanumeric(char):
    """
    Returns the hex equivalent of the given character in the form 3C
    """
    # Disabled for unicode
    #if ord(char) > 0xFF: return None
    if ('0' <= char <= '9' or
        'a' <= char <= 'z' or
        'A' <= char <= 'Z'):
        return None
    else:
        return hex(ord(char))[2:].upper()

class Codec():
    """
    The Codec interface defines a set of methods for encoding and decoding 
    application level encoding schemes, such as HTML entity encoding and 
    percent encoding (aka URL encoding). Codecs are used in output encoding
    and canonicalization.  The design of these codecs allows for 
    character-by-character decoding, which is necessary to detect 
    double-encoding and the use of multiple encoding schemes, both of which are
    techniques used by attackers to bypass validation and bury encoded attacks
    in data.

    @author Craig Younkins (craig.younkins@owasp.org)
    @see esapi.encoder
    """
    
    def __init__(self):
        pass
           
    def encode(self, immune, raw):
        """
        Encode a String so that it can be safely used in a specific context.

        @param immune
        @param raw
                the String to encode
        @return the encoded String
        """    
        ret = ''
        for char in raw:
            ret += self.encode_character(immune, char)
        return ret
        
    def encode_character(self, immune, char):
        """
        Default implementation that should be overridden in specific codecs.

        @param immune
        @param c
                the Character to encode
        @return
                the encoded Character
        """
        raise NotImplementedError()
        
    def decode(self, encoded):
        """
        Decode a String that was encoded using the encode method in this Class

        @param encoded
                the String to decode
        @return
                the decoded String
        """
        buf = ''
        pbs = PushbackString(encoded)
        while pbs.has_next():
            char = self.decode_character(pbs)
            if char is not None:
                buf += char
            else:
                buf += pbs.next()
        return buf
        
    def decode_character(self, pbs):
        """
        Returns the decoded version of the next character from the input 
        string and advances the current character in the PushbackString.  
        If the current character is not encoded, this method MUST reset the 
        PushbackString.

        @param pbs	the PushBackString to decode a character from

        @return the decoded Character
        """
        raise NotImplementedError()