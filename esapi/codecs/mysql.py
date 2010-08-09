#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: Implementation of the Codec interface for MySQL strings.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

import esapi.codecs.codec as codec

class BadModeError(): pass

class MySQLCodec(codec.Codec):
    """
    Implementation of the Codec interface for MySQL strings. See 
    U{here<http://dev.mysql.com/doc/refman/5.0/en/string-syntax.html>}
    or more information.
    """
    
    MYSQL_MODE = 0
    ANSI_MODE = 1
   
    def __init__(self, mode):
        """
        Instantiates the MySQL codec.
        
        @param mode: Either MySQLCodec.MYSQL_MODE or MySQLCodec.ANSI_MODE,
            changes the encoding
        """
        codec.Codec.__init__(self)
        if mode != MySQLCodec.MYSQL_MODE and mode != MySQLCodec.ANSI_MODE:
            raise BadModeError()
        self.mode = mode
    
    def encode_character(self, immune, char):
        """
        Returns a quote-encoded character.
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
            
        if self.mode == MySQLCodec.MYSQL_MODE:
            return self.encode_character_mysql(char, ord_char)
        elif self.mode == MySQLCodec.ANSI_MODE:
            return self.encode_character_ansi(char)
        else:
            raise BadModeError()
        
        return None
        
    def encode_character_ansi(self, char):
        """
        Encodes character for ANSI SQL.
        Only the apostrophe is encoded.
        """
        
        if char == "'":
            return "''"
            
        return char
        
    def encode_character_mysql(self, char, ord_char):
        """
        Encodes a character for MySQL.
        """
        lookup = {
        0x00 : "\\0",
        0x08 : "\\b",
        0x09 : "\\t",
        0x0a : "\\n",
        0x0d : "\\r",
        0x1a : "\\Z",
        0x22 : '\\"',
        0x25 : "\\%",
        0x27 : "\\'",
        0x5c : "\\\\",
        0x5f : "\\_",
        }
        
        if lookup.has_key(ord_char):
            return lookup[ord_char]
            
        return "\\" + char
    
    def decode_character(self, pbs):
        """
        Returns the decoded version of the character starting at index, or
        None if no decoding is possible.
        
        Formats all are legal (case sensitive)
        In ANSI_MODE '' decodes to '
        In MYSQL_MODE \\x decodes to x (or a small list of specials)
        """
        if self.mode == MySQLCodec.MYSQL_MODE:
            return self.decode_character_mysql(pbs)
        elif self.mode == MySQLCodec.ANSI_MODE:
            return self.decode_character_ansi(pbs)
        else:
            raise BadModeError()
        
        return None
        
    def decode_character_ansi(self, pbs):
        """
        Decodes the next character from an ANSI SQL escaping.
        
        @param pbs: A PushbackString with the characters you want to decode
        @return: a single character, decoded
        """
        pbs.mark()
        
        first = pbs.next()
        if first is None:
            pbs.reset()
            return None
            
        # if this is not an encoded character, return None
        if first != "'":
            pbs.reset()
            return None
            
        second = pbs.next()
        if second is None:
            pbs.reset()
            return None
            
        # if this is not THE encoded character, return None
        if second != "'":
            pbs.reset()
            return None
            
        return "'"
        
    def decode_character_mysql(self, pbs):
        """
        Decode the next character in the PushbackString according to MySQL 
        mode.
        
        @param pbs: A PushbackString to decode the next character from
        @return: the next character, decoded
        """
        pbs.mark()
        
        # Will always be true because pbs.has_next() in codec.decode
        first = pbs.next()
            
        # if this is not an encoded character, return None
        if first != "\\":
            pbs.reset()
            return None
            
        second = pbs.next()
        if second is None:
            pbs.reset()
            return None
            
        lookup = {
        "\\0" : 0x00,
        "\\b" : 0x08,
        "\\t" : 0x09,
        "\\n" : 0x0a,
        "\\r" : 0x0d,
        "\\Z" : 0x1a,
        '\\"' : 0x22,
        "\\%" : 0x25,
        "\\'" : 0x27,
        "\\\\" : 0x5c,
        "\\_" : 0x5f,
        }
        
        if lookup.has_key(first + second):
            return unichr(lookup[first + second])
            
        return second
