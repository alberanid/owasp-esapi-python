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

import esapi.core
from esapi.encoder import Encoder
from esapi.codecs.percent_codec import PercentCodec
from esapi.logger import Logger

class DefaultEncoder(Encoder):
    """
    Reference implementation of the Encoder interface. This implementation takes
    a whitelist approach to encoding, meaning that everything not specifically 
    identified in a list of "immune" characters is encoded.

    @author Craig Younkins (craig.younkins@owasp.org)
    """
    
    codecs = []
    #htmlCodec = HTMLEntityCodec()
    _percent_codec = PercentCodec()
    #javaScriptCodec = JavaScriptCodec()
    #vbScriptCodec = VBScriptCodec()
    #cssCodec = CSSCodec()
    
    logger = esapi.core.getLogger("Encoder")
    
    IMMUNE_HTML = ',.-_ '
    IMMUNE_HTMLATTR = ',.-_'
    IMMUNE_CSS = ''
    IMMUNE_JAVASCRIPT = ',._'
    IMMUNE_XML = ',.-_ '
    IMMUNE_SQL = ' '
    IMMUNE_OS = '-'
    IMMUNE_XMLATTR = ',.-_'
    IMMUNE_XPATH = ',.-_ '
    
    # Unreserved characters as specified in RFC 3986
    IMMUNE_URL = '-_.~'
    
    def __init__(self, codecs=None):
        if codecs is None:
            #self.codecs.append(self.html_codec)
            self.codecs.append(self._percent_codec)
            #self.codecs.append(self.javascript_codec)
        else:
            self.codecs = codecs

    def canonicalize(self, input, strict=True):
        if input is None: return None
        
        working = input[:]
        codecs_found = []
        found_count = 0
        clean = False
        
        while not clean:
            clean = True
            
            # Try each codec and keep track of which ones work
            for codec in self.codecs:
                old = working[:]
                working = codec.decode( working )
                if old != working:
                    if codec.__class__.__name__ not in codecs_found:
                        codecs_found.append(codec.__class__.__name__)
                    if clean:
                        found_count += 1
                    clean = False
                    
        if found_count >= 2 and len(codecs_found) > 1:
            if strict:
                raise IntrusionException( "Input validation failure", 
                "Multiple (%sx) and mixed encoding (%s) detected in %s" %
                (found_count, str(codecs_found), input))
            else:
                self.logger.warning( Logger.SECURITY_FAILURE, 
                "Multiple (%sx) and mixed encoding (%s) detected in %s" %
                (found_count, str(codecs_found), input))
            
        elif found_count >= 2:
            if strict:
                raise IntrusionException( "Input validation failure",
                "Multiple (%sx) encoding detected in %s" %
                (found_count, input))
            else:
                self.logger.warning( Logger.SECURITY_FAILURE,
                "Multiple (%sx) encoding detected in %s" %
                (found_count, input))
                
        elif len(codecs_found) > 1:
            if strict:
                raise IntrusionException( "Input validation failure",
                "Mixed encoding (%s) detected in %s" % 
                (str(codecs_found), input))
            else:
                self.logger.warning( Logger.SECURITY_FAILURE,
                "Mixed encoding (%s) detected in %s" % 
                (str(codecs_found), input))
                
        return working
        
    def normalize(self, input):
        raise NotImplementedError()

    def encodeForCSS(self, input):
        raise NotImplementedError()

    def encodeForHTML(self, input):
        raise NotImplementedError()

    def encodeForHTMLAttribute(self, input):
        raise NotImplementedError()

    def encodeForJavaScript(self, input):
        raise NotImplementedError()

    def encodeForVBScript(self, input):
        raise NotImplementedError()

    def encodeForSQL(self, codec, input):
        raise NotImplementedError()

    def encodeForOS(self, codec, input):
        raise NotImplementedError()

    def encodeForLDAP(self, input):
        raise NotImplementedError()

    def encodeForDN(self, input):
        raise NotImplementedError()

    def encodeForXPath(self, input):
        raise NotImplementedError()

    def encodeForXML(self, input):
        raise NotImplementedError()

    def encodeForXMLAttribute(self, input):
        raise NotImplementedError()

    def encode_for_url(self, input):
        if input is None: return None
        
        return self._percent_codec.encode(self.IMMUNE_URL, input)

    def decode_from_url(self, input):
        if input is None: return None
        
        canonical = self.canonicalize(input)
        return self._percent_codec.decode(canonical)

    def encodeForBase64(self, input, wrap):
        options = 0
        if not wrap:
            options |= Base64.DONT_BREAK_LINES
        return Base64.encode(input, options)

    def decodeFromBase64(self, input):
        raise NotImplementedError()


