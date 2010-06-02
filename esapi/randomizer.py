#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: The Randomizer interface defines a set of methods for creating
    cryptographically random numbers and strings.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

from esapi.conf.constants import MAX_INTEGER, MIN_INTEGER, MAX_FLOAT, MIN_FLOAT

class Randomizer():
    """
    The Randomizer interface defines a set of methods for creating
    cryptographically random numbers and strings. Implementers should be sure to
    use a strong cryptographic implementation, such as random.SystemRandom.
    Weak sources of randomness can undermine a wide variety of security
    mechanisms. The specific algorithm used is configurable in settings.py.

    @author: Craig Younkins (craig.younkins@owasp.org)
    """
    
    def __init__(self):
        pass

    def get_random_string(self, length, character_set):
        """
        Gets a random string of a desired length and character set.  The use of
        random.SystemRandom is recommended because it provides a 
        cryptographically strong pseudo-random number generator. If 
        random.SystemRandom is not used, the pseudo-random number gernerator 
        used should comply with the statistical random number generator tests 
        specified in U{FIPS 140-2, Security Requirements for Cryptographic Modules<http://csrc.nist.gov/cryptval/140-2.htm>}, 
        section 4.9.1.

        @param length: the length of the string
        @param character_set: the set of characters to include in the created random string
        @return: the random string of the desired length and character set
        """
        raise NotImplementedError()

    def get_random_boolean(self):
        """
        Returns a random boolean.  The use of random.SystemRandom
        is recommended because it provides a cryptographically strong 
        pseudo-random number generator. If random.SystemRandom is not used, 
        the pseudo-random number gernerator used should comply with the 
        statistical random number generator tests specified in 
        U{FIPS 140-2, Security Requirements for Cryptographic Modules<http://csrc.nist.gov/cryptval/140-2.htm>}, 
        section 4.9.1.

        @return: true or false, randomly
        """
        raise NotImplementedError()

    def get_random_integer(self, min_=MIN_INTEGER, max_=MAX_INTEGER):
        """
        Returns a random integer or long.  The use of random.SystemRandom
        is recommended because it provides a cryptographically strong 
        pseudo-random number generator. If random.SystemRandom is not used, 
        the pseudo-random number gernerator used should comply with the 
        statistical random number generator tests specified in 
        U{FIPS 140-2, Security Requirements for Cryptographic Modules<http://csrc.nist.gov/cryptval/140-2.htm>}, 
        section 4.9.1.

        The lower bound (minimum) is inclusive and the upper bound (max) is also inclusive.
        
        @param min_: the minimum integer that will be returned
        @param max_: the maximum integer that will be returned

        @return: the random integer
        """
        raise NotImplementedError()

    def get_random_filename(self, extension):
        """
        Returns an unguessable random filename with the specified extension.  
        This method could call getRandomString(length, charset) from this 
        Class with the desired length and alphanumerics as the charset then 
        merely append "." + extension.

        @param extension: extension to add to the random filename

        @return: a random unguessable filename ending with the specified extension
        """
        raise NotImplementedError()
       
    def get_random_float(self, min_=MIN_FLOAT, max_=MAX_FLOAT):
        """
        Returns a random floating point number.  The use of random.SystemRandom
        is recommended because it provides a cryptographically strong 
        pseudo-random number generator. If random.SystemRandom is not used, 
        the pseudo-random number gernerator used should comply with the 
        statistical random number generator tests specified in 
        U{FIPS 140-2, Security Requirements for Cryptographic Modules<http://csrc.nist.gov/cryptval/140-2.htm>}, 
        section 4.9.1.

        The lower bound (minimum) is inclusive and the upper bound (max) is also inclusive.
        
        @param min_: the minimum float that will be returned
        @param max_: the maximum float that will be returned

        @return: the random float
        """
        raise NotImplementedError()

    def get_random_guid(self):
        """
        Generates a random GUID according to 
        U{RFC 4122 V4<http://tools.ietf.org/html/rfc4122#section-4.1.3>}.
        This should set the version to '4', and satisfy the high-bit 
        requirement by setting the correct position to '8','9','a', or 'b'.  
        The format is a well-defined sequence of 32 hex digits grouped into 
        chunks of 8-4-4-4-12.

        @return: the GUID
        """
        raise NotImplementedError()

    def get_random_choice(self, seq):
        """
        Selects a random element from the sequence.
        
        @param seq: a sequence to select a random element from
        
        @return: the random element
        """
        raise NotImplementedError()
    