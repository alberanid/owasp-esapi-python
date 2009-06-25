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

import base64

from esapi.core import ESAPI
from esapi.encoder import Encoder

from esapi.codecs.percent import PercentCodec
from esapi.codecs.html_entity import HTMLEntityCodec
from esapi.codecs.javascript import JavascriptCodec

from esapi.logger import Logger

class DefaultEncoder(Encoder):
    """
    Reference implementation of the Encoder interface. This implementation 
    takes a whitelist approach to encoding, meaning that everything not 
    specifically identified in a list of "immune" characters is encoded.

    @author Craig Younkins (craig.younkins@owasp.org)
    """
    
    codecs = []
    _html_codec = HTMLEntityCodec()
    _percent_codec = PercentCodec()
    _javascript_codec = JavascriptCodec()
    #vbScriptCodec = VBScriptCodec()
    #cssCodec = CSSCodec()
    
    logger = ESAPI.logger("Encoder")
    
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
        Encoder.__init__(self)
        if codecs is None:
            self.codecs.append(self._html_codec)
            self.codecs.append(self._percent_codec)
            self.codecs.append(self._javascript_codec)
        else:
            self.codecs = codecs

    def canonicalize(self, input_, strict=True):
        if input_ is None: 
            return None
        
        working = input_[:]
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
                (found_count, str(codecs_found), input_))
            else:
                self.logger.warning( Logger.SECURITY_FAILURE, 
                "Multiple (%sx) and mixed encoding (%s) detected in %s" %
                (found_count, str(codecs_found), input_))
            
        elif found_count >= 2:
            if strict:
                raise IntrusionException( "Input validation failure",
                "Multiple (%sx) encoding detected in %s" %
                (found_count, input_))
            else:
                self.logger.warning( Logger.SECURITY_FAILURE,
                "Multiple (%sx) encoding detected in %s" %
                (found_count, input_))
                
        elif len(codecs_found) > 1:
            if strict:
                raise IntrusionException( "Input validation failure",
                "Mixed encoding (%s) detected in %s" % 
                (str(codecs_found), input_))
            else:
                self.logger.warning( Logger.SECURITY_FAILURE,
                "Mixed encoding (%s) detected in %s" % 
                (str(codecs_found), input_))
                
        return working
        
    def normalize(self, input_):
        raise NotImplementedError()

    def encode_for_css(self, input_):
        raise NotImplementedError()

    def encode_for_html(self, input_):
        raise NotImplementedError()

    def encode_for_html_attribute(self, input_):
        raise NotImplementedError()

    def encode_for_javascript(self, input_):
        raise NotImplementedError()

    def encode_for_vbscript(self, input_):
        raise NotImplementedError()

    def encode_for_sql(self, codec, input_):
        raise NotImplementedError()

    def encode_for_os(self, codec, input_):
        raise NotImplementedError()

    def encode_for_ldap(self, input_):
        raise NotImplementedError()

    def encode_for_dn(self, input_):
        raise NotImplementedError()

    def encode_for_xpath(self, input_):
        raise NotImplementedError()

    def encode_for_xml(self, input_):
        raise NotImplementedError()

    def encode_for_xml_attribute(self, input_):
        raise NotImplementedError()

    def encode_for_url(self, input_):
        if input_ is None: 
            return None
        
        return self._percent_codec.encode(self.IMMUNE_URL, input_)

    def decode_from_url(self, input_):
        if input_ is None: 
            return None
        
        canonical = self.canonicalize(input_)
        return self._percent_codec.decode(canonical)

    def encode_for_base64(self, input_):
        return base64.b64encode(input_)

    def decode_from_base64(self, input_):
        return base64.b64decode(input_)


