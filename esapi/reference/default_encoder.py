#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@copyright: Copyright (c) 2009 - The OWASP Foundation
@summary: Reference implementation of the Encoder interface.
@author: Craig Younkins (craig.younkins@owasp.org)
"""

import base64

from esapi.core import ESAPI
from esapi.encoder import Encoder
from esapi.logger import Logger
from esapi.translation import _

from esapi.codecs.codec import Codec
from esapi.codecs.css import CSSCodec
from esapi.codecs.html_entity import HTMLEntityCodec
from esapi.codecs.javascript import JavascriptCodec
from esapi.codecs.percent import PercentCodec
from esapi.codecs.vbscript import VBScriptCodec
from esapi.codecs.ldap_dn import LDAPDNCodec
from esapi.codecs.ldap import LDAPCodec

from esapi.exceptions import EncodingException
from esapi.exceptions import IntrusionException

class DefaultEncoder(Encoder):
    """
    Reference implementation of the Encoder interface. This implementation 
    takes a whitelist approach to encoding, meaning that everything not 
    specifically identified in a list of "immune" characters is encoded.

    @author: Craig Younkins (craig.younkins@owasp.org)
    """
    
    IMMUNE_HTML = ',.-_ '
    IMMUNE_HTMLATTR = ',.-_'
    IMMUNE_CSS = ''
    IMMUNE_JAVASCRIPT = ',._'
    IMMUNE_VBSCRIPT = ',._'
    IMMUNE_XML = ',.-_ '
    IMMUNE_SQL = ' '
    IMMUNE_OS = '-'
    IMMUNE_XMLATTR = ',.-_'
    IMMUNE_XPATH = ',.-_ '
    IMMUNE_LDAP = ''
    IMMUNE_LDAP_DN = ''
    
    # Unreserved characters as specified in RFC 3986
    IMMUNE_URL = '-_.~'
    
    def __init__(self, codecs=None):
        """
        Instantiates a new DefaultEncoder.
        
        @param codecs: : a list of codec instances to use for canonicalization
        """
        Encoder.__init__(self)
        
        self.html_codec = HTMLEntityCodec()
        self.percent_codec = PercentCodec()
        self.javascript_codec = JavascriptCodec()
        self.vbscript_codec = VBScriptCodec()
        self.css_codec = CSSCodec()
        self.ldap_codec = LDAPCodec()
        self.ldap_dn_codec = LDAPDNCodec()
    
        self.logger = ESAPI.logger("Encoder")
        
        # Used for canonicalization
        self.codecs = []
        if codecs is None:
            self.codecs.append(self.html_codec)
            self.codecs.append(self.percent_codec)
            self.codecs.append(self.javascript_codec)
            
            # Leaving out css_codec because it eats / characters
            # Leaving out vbscript_codec because it eats " characters
        else:
            for codec in codecs:
                if not isinstance(codec, Codec):
                    raise TypeError(_("Codecs in list must be instances of children of Codec"))
                self.codecs.append(codec)
                    
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
                raise IntrusionException( _("Input validation failure"), 
                    _("Multiple (%(times_encoded)sx) and mixed encoding (%(codecs_found)s) detected in %(input)s") %
                    {'times_encoded' : found_count, 
                     'codecs_found' : str(codecs_found), 
                     'input' : input_})
                
            else:
                self.logger.warning( Logger.SECURITY_FAILURE, 
                    _("Multiple (%s(times_encoded)x) and mixed encoding (%(codecs_found)s) detected in %(input)s") %
                    {'times_encoded' : found_count, 
                     'codecs_found' : str(codecs_found), 
                     'input' : input_})
            
        elif found_count >= 2:
            if strict:
                raise IntrusionException( _("Input validation failure"),
                    _("Multiple (%s(times_encoded)x) encoding detected in %(input)s") %
                    {'times_encoded' : found_count, 
                     'input' : input_})
            else:
                self.logger.warning( Logger.SECURITY_FAILURE,
                    _("Multiple (%s(times_encoded)x) encoding detected in %(input)s") %
                    {'times_encoded' : found_count, 
                     'input' : input_})
                
        elif len(codecs_found) > 1:
            if strict:
                raise IntrusionException( _("Input validation failure"),
                    _("Mixed encoding (%(codecs_found)s) detected in %(input)s") % 
                    {'codecs_found' : str(codecs_found), 
                     'input' : input_})
            else:
                self.logger.warning( Logger.SECURITY_FAILURE,
                    _("Mixed encoding (%(codecs_found)s) detected in %(input)s") % 
                    {'codecs_found' : str(codecs_found), 
                     'input' : input_})
                
        return working

    def encode_for_css(self, input_):
        return self.css_codec.encode( DefaultEncoder.IMMUNE_CSS, input_ )

    def encode_for_html(self, input_):
        return self.html_codec.encode( DefaultEncoder.IMMUNE_HTML, input_ )

    def encode_for_html_attribute(self, input_):
        return self.html_codec.encode( DefaultEncoder.IMMUNE_HTMLATTR, input_ )

    def encode_for_javascript(self, input_):
        return self.javascript_codec.encode( DefaultEncoder.IMMUNE_JAVASCRIPT, input_ )

    def encode_for_vbscript(self, input_):
        return self.vbscript_codec.encode( DefaultEncoder.IMMUNE_VBSCRIPT, input_ )

    def encode_for_sql(self, codec, input_):
        return codec.encode( DefaultEncoder.IMMUNE_SQL, input_ )

    def encode_for_os(self, codec, input_):
        return codec.encode( DefaultEncoder.IMMUNE_OS, input_ )

    def encode_for_ldap(self, input_):
        return self.ldap_codec.encode( DefaultEncoder.IMMUNE_LDAP, input_ )

    def encode_for_dn(self, input_):
        return self.ldap_dn_codec.encode( DefaultEncoder.IMMUNE_LDAP_DN, input_ )

    def encode_for_xpath(self, input_):
        return self.html_codec.encode( DefaultEncoder.IMMUNE_XPATH, input_ )

    def encode_for_xml(self, input_):
        return self.html_codec.encode( DefaultEncoder.IMMUNE_XML, input_ )

    def encode_for_xml_attribute(self, input_):
        return self.html_codec.encode( DefaultEncoder.IMMUNE_XMLATTR, input_ )

    def encode_for_url(self, input_):
        return self.percent_codec.encode(DefaultEncoder.IMMUNE_URL, input_)

    def decode_from_url(self, input_):
        if input_ is None:
            return None
        canonical = self.canonicalize(input_)
        return self.percent_codec.decode(canonical)

    def encode_for_base64(self, input_):
        try:
            return base64.b64encode(input_)
        except:
            return None

    def decode_from_base64(self, input_):
        try:
            return base64.b64decode(input_)
        except:
            return None
