"""
OWASP Enterprise Security API (ESAPI)
 
This file is part of the Open Web Application Security Project (OWASP)
Enterprise Security API (ESAPI) project. For details, please see
<a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
Copyright (c) 2009 - The OWASP Foundation

The ESAPI is published by OWASP under the BSD license. You should read and accept the
LICENSE before you use, modify, and/or redistribute this software.

@author Craig Younkins (craig.younkins@owasp.org)
"""

class Randomizer():
    """
    The Randomizer interface defines a set of methods for creating
    cryptographically random numbers and strings. Implementers should be sure to
    use a strong cryptographic implementation, such as random.SystemRandom.
    Weak sources of randomness can undermine a wide variety of security
    mechanisms. The specific algorithm used is configurable in settings.py.

    @author Craig Younkins (craig.younkins@owasp.org)
    """

    def getRandomString(self, length, characterSet):
        """
        Gets a random string of a desired length and character set.  The use of random.SystemRandom
        is recommended because it provides a cryptographically strong pseudo-random number generator.
        If random.SystemRandom is not used, the pseudo-random number gernerator used should comply with the
        statistical random number generator tests specified in <a href="http://csrc.nist.gov/cryptval/140-2.htm">
        FIPS 140-2, Security Requirements for Cryptographic Modules</a>, section 4.9.1.

        @param length
                the length of the string
        @param characterSet
                the set of characters to include in the created random string
        @return
                the random string of the desired length and character set
        """
        raise NotImplementedError()

    def getRandomBoolean(self):
        """
        Returns a random boolean.  The use of random.SystemRandom
        is recommended because it provides a cryptographically strong pseudo-random number generator.
        If random.SystemRandom is not used, the pseudo-random number gernerator used should comply with the
        statistical random number generator tests specified in <a href="http://csrc.nist.gov/cryptval/140-2.htm">
        FIPS 140-2, Security Requirements for Cryptographic Modules</a>, section 4.9.1.

        @return
                true or false, randomly
        """
        raise NotImplementedError()

    def getRandomInteger(self, min, max):
        """
        Gets a random integer or long. The use of random.SystemRandom
        is recommended because it provides a cryptographically strong pseudo-random number generator.
        If random.SystemRandom is not used, the pseudo-random number gernerator used should comply with the
        statistical random number generator tests specified in <a href="http://csrc.nist.gov/cryptval/140-2.htm">
        FIPS 140-2, Security Requirements for Cryptographic Modules</a>, section 4.9.1.

        The lower bound (minimum) is inclusive and the upper bound (max) is also inclusive.
        
        @param min
                the minimum integer that will be returned
        @param max
                the maximum integer that will be returned

        @return
                the random integer
        """
        raise NotImplementedError()

    def getRandomFilename(self, extension):
        """
        Returns an unguessable random filename with the specified extension.  This method could call
        getRandomString(length, charset) from this Class with the desired length and alphanumerics as the charset
        then merely append "." + extension.

        @param extension
                extension to add to the random filename

        @return
                a random unguessable filename ending with the specified extension
        """
        raise NotImplementedError()
       
    def getRandomFloat(self, min, max):
        """
        Gets a random floating point number. The use of random.SystemRandom
        is recommended because it provides a cryptographically strong pseudo-random number generator.
        If random.SystemRandom is not used, the pseudo-random number gernerator used should comply with the
        statistical random number generator tests specified in <a href="http://csrc.nist.gov/cryptval/140-2.htm">
        FIPS 140-2, Security Requirements for Cryptographic Modules</a>, section 4.9.1.

        The lower bound (minimum) is inclusive and the upper bound (max) is also inclusive.
        
        @param min
                the minimum float that will be returned
        @param max
                the maximum float that will be returned

        @return
                the random float
        """
        raise NotImplementedError()

    def getRandomGUID(self):
        """
        Generates a random GUID according to <a href="http://tools.ietf.org/html/rfc4122#section-4.1.3">RFC 4122 V4</a>.
        This should set the version to '4', and satisfy the high-bit requirement by setting the correct position to 
        '8','9','a', or 'b'.  The format is a well-defined sequence of 32 hex digits grouped into chunks of 8-4-4-4-12.

        @return
                the GUID
        """
        raise NotImplementedError()

    def getRandomChoice(self, seq):
        """
        Selects a random element from the sequence.
        
        @param seq  a sequence to select a random element from
        
        @return  the random element
        """
        raise NotImplementedError()
    