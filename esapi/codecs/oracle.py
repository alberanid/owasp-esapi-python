#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: Implementation of the Codec interface for Oracle strings.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

import esapi.codecs.codec as codec

class OracleCodec(codec.Codec):
    """
    Implementation of the Codec interface for Oracle strings. This class will
    only protect you from SQL injection when user data is placed within an
    Oracle quoted string such as:
    
    select * from table where user_name='  USERDATA    ';
  
    @see: U{How to escape single quotes in strings<http://oraqa.com/2006/03/20/how-to-escape-single-quotes-in-strings/>}
    """
   
    def __init__(self):
        """
        Instantiates the Oracle codec.
        """
        codec.Codec.__init__(self)
    
    def encode_character(self, immune, char):
        """
        Encodes ' to ''
        """
        
        if char == "'":
            return "''"
            
        return char
    
    def decode_character(self, pbs):
        """
        Returns the decoded version of the character starting at index, or
        None if no decoding is possible.
        
        '' decodes to '
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
            
        if second != "'":
            pbs.reset()
            return None
            
        return "'"
        
