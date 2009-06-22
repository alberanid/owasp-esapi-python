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

def is_hex_digit(c):
    """
    Returns true if the parameter character is a hexadecimal digit 0
    through 9, a through f, or A through F.
    """
    if c is None: return False
    return ((c >= '0' and c <= '9') or 
           (c >= 'a' and c <= 'f') or 
           (c >= 'A' and c <= 'F'))
           
def is_octal_digit(c):
    """
    Returns true if the parameter character is an octal digit between
    0 through 7.
    """
    if c is None: return False
    return c >= '0' and c <= '7'


class PushbackString:
    """
    The pushback string is used by Codecs to allow them to push decoded 
    characters back onto a string for further decoding. This is necessary to 
    detect double-encoding.
    """

    _input = None
    _pushback = None
    _temp = None
    _index = 0
    _mark = 0

    def __init__(self, input_):
        self._input = input_
    
    def pushback(self, c):
        self._pushback = c
        
    def index(self):
        """
        Get the current index of the PushbackString. Typically used in error
        messages.
        """
        return self._index
        
    def has_next(self):
        if self._pushback is not None: return True
        if self._input is None: return False
        if len(self._input) == 0: return False
        if self._index >= len(self._input): return False
        return True
    
    def next(self):
        if self._pushback is not None:
            save = self._pushback
            self._pushback = None
            return save
        
        if self._input is None: return None
        if len(self._input) == 0: return None
        if self._index >= len(self._input): return None
        ret = self._input[self._index]
        self._index += 1
        return ret
        
    def next_hex(self):
        c = self.next()
        if c is None: return None
        if is_hex_digit(c): return c
        return None
        
    def next_octal(self):
        c = self.next()
        if c is None: return None
        if is_octal_digit(c): return c
        return None
        
    def peek(self, test_char=None):
        if test_char:
            if self._pushback is None and self._pushback == test_char: 
                return True
            if self._input is None: return False
            if len(self._input) == 0: return False
            if self._index >= len(self._input): return False
            return self._input[self._index] == test_char
            
        if not test_char:
            if self._pushback is not None: return self._pushback
            if self._input is None: return None
            if len(self._input) == 0: return None
            if self._index >= len(self._input): return None
            
            return self._input[self._index]
            
    def mark(self):
        self._temp = self._pushback
        self._mark = self._index
        
    def reset(self):
        self._pushback = self._temp
        self._index = self._mark
        
    def remainder(self):
        output = self._input[self._index:]
        if self._pushback:
            output = self._pushback + output
        return output