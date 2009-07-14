#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: Implementation of the Codec interface for LDAP encoding.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

import esapi.codecs.codec as codec

class LDAPCodec(codec.Codec):
    """
    Implementation of the Codec interface for LDAP encoding.
    """
   
    def __init__(self):
        """
        Instantiates the LDAP codec.
        """
        codec.Codec.__init__(self)
    
    def encode_character(self, immune, char):
        """
        Returns a character encoded for LDAP.
        """
        # Check for immunes
        if char in immune:
            return char
            
        replacement = {
            '\\' : '\\5c',
            '*'  : '\\2a',
            '('  : '\\28',
            ')'  : '\\29',
            unichr(0) : '\\00',
            }
            
        if replacement.has_key(char):
            return replacement[char]
            
        return char
        
    def decode(self, encoded):
        raise NotImplementedError()
    
    def decode_character(self, pbs):
        raise NotImplementedError()