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

class LDAPDNCodec(Codec):
    """
    Implementation of the Codec interface for LDAP distinguished name encoding.
    """
   
    def __init__(self):
        """
        Instantiates the LDAP DN codec.
        """
        Codec.__init__(self)
        
    def encode(self, immune, raw):
        """
        Encode a String so that it can be safely used in an LDAP distinguished
        name.

        @param immune
        @param raw
                the String to encode
        @return the encoded String
        """    
        ret = ''
        
        # Add the leading backslash if needed
        if  len(raw) > 0 and (raw[0] == ' ' or raw[0] == '#'):
            ret += '\\'
            
        try:
            for char in raw:
                ret += self.encode_character(immune, char)
        except TypeError:
            return None
            
        # Add the trailing backslash if needed
        if len(raw) > 1 and raw[-1] == ' ':
            ret = ret[:-1] + "\\" + ret[-1]
            
        return ret
    
    def encode_character(self, immune, char):
        """
        
        """
        # Check for immunes
        if char in immune:
            return char
            
        replacement = {
            '\\' : '\\\\',
            ','  : '\\,',
            '+'  : '\\+',
            '"'  : '\\"',
            '<'  : '\\<',
            '>'  : '\\>',
            ';'  : '\\;',
            }
            
        if replacement.has_key(char):
            return replacement[char]
            
        return char
        
    def decode(self, encoded):
        raise NotImplementedError()
    
    def decode_character(self, pbs):
        raise NotImplementedError()