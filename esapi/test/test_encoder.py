#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: Test suite for Encoder implementation.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

# Use esapi/test/conf instead of esapi/conf
# It is important that this is at the top, as it affects the imports below
# by loading the test configuration instead of the normal one.
# This should ONLY ever be used in the unit tests.
import esapi.test.conf

import unittest
import threading
import time

from esapi.core import ESAPI
from esapi.codecs.push_back_string import PushbackString
from esapi.encoder import Encoder

from esapi.codecs.css import CSSCodec
from esapi.codecs.html_entity import HTMLEntityCodec
from esapi.codecs.percent import PercentCodec
from esapi.codecs.javascript import JavascriptCodec
from esapi.codecs.mysql import MySQLCodec, BadModeError
from esapi.codecs.vbscript import VBScriptCodec
from esapi.codecs.oracle import OracleCodec
from esapi.codecs.windows import WindowsCodec
from esapi.codecs.unix import UnixCodec

from esapi.exceptions import IntrusionException

PLAIN = 0
ENCODED = 1
ALT_ENCODINGS = 2

class EncoderTest(unittest.TestCase):
    
    def __init__(self, test_name=""):
        """
        @param test_name: the test name
        """
        unittest.TestCase.__init__(self, test_name)
        
    def test_encoder_constructor_exception(self):
        """
        Checks that only valid codecs are allowed.
        """
        codecs = [CSSCodec(), str]
        self.assertRaises(TypeError, ESAPI.encoder, codecs)
            
    def test_canonicalize(self):
        codecs = [HTMLEntityCodec(), PercentCodec()]
        encoder_class = ESAPI.security_configuration().get_class_for_interface('encoder')
        instance = encoder_class(codecs)
        
        # Test None paths
        self.assertEquals( None, instance.canonicalize(None))
        self.assertEquals( None, instance.canonicalize(None, True))
        self.assertEquals( None, instance.canonicalize(None, False))
        
        # test exception paths
        self.assertEquals( "%", instance.canonicalize("%25", True))
        self.assertEquals( "%", instance.canonicalize("%25", False))
        
        self.assertEquals( "%", instance.canonicalize("%25"))
        self.assertEquals( "%F", instance.canonicalize("%25F"))
        self.assertEquals( "<", instance.canonicalize("%3c"))
        self.assertEquals( "<", instance.canonicalize("%3C"))
        self.assertEquals( "%X1", instance.canonicalize("%X1"))

        self.assertEquals( "<", instance.canonicalize("&lt"))
        self.assertEquals( "<", instance.canonicalize("&LT"))
        self.assertEquals( "<", instance.canonicalize("&lt;"))
        self.assertEquals( "<", instance.canonicalize("&LT;"))
        
        self.assertEquals( "%", instance.canonicalize("&#37;"))
        self.assertEquals( "%", instance.canonicalize("&#37"))
        self.assertEquals( "%b", instance.canonicalize("&#37b"))

        self.assertEquals( "<", instance.canonicalize("&#x3c"))
        self.assertEquals( "<", instance.canonicalize("&#x3c;"))
        self.assertEquals( "<", instance.canonicalize("&#x3C"))
        self.assertEquals( "<", instance.canonicalize("&#X3c"))
        self.assertEquals( "<", instance.canonicalize("&#X3C"))
        self.assertEquals( "<", instance.canonicalize("&#X3C;"))

        # percent encoding
        self.assertEquals( "<", instance.canonicalize("%3c"))
        self.assertEquals( "<", instance.canonicalize("%3C"))

        # html entity encoding
        self.assertEquals( "<", instance.canonicalize("&#60"))
        self.assertEquals( "<", instance.canonicalize("&#060"))
        self.assertEquals( "<", instance.canonicalize("&#0060"))
        self.assertEquals( "<", instance.canonicalize("&#00060"))
        self.assertEquals( "<", instance.canonicalize("&#000060"))
        self.assertEquals( "<", instance.canonicalize("&#0000060"))
        self.assertEquals( "<", instance.canonicalize("&#60;"))
        self.assertEquals( "<", instance.canonicalize("&#060;"))
        self.assertEquals( "<", instance.canonicalize("&#0060;"))
        self.assertEquals( "<", instance.canonicalize("&#00060;"))
        self.assertEquals( "<", instance.canonicalize("&#000060;"))
        self.assertEquals( "<", instance.canonicalize("&#0000060;"))
        self.assertEquals( "<", instance.canonicalize("&#x3c"))
        self.assertEquals( "<", instance.canonicalize("&#x03c"))
        self.assertEquals( "<", instance.canonicalize("&#x003c"))
        self.assertEquals( "<", instance.canonicalize("&#x0003c"))
        self.assertEquals( "<", instance.canonicalize("&#x00003c"))
        self.assertEquals( "<", instance.canonicalize("&#x000003c"))
        self.assertEquals( "<", instance.canonicalize("&#x3c;"))
        self.assertEquals( "<", instance.canonicalize("&#x03c;"))
        self.assertEquals( "<", instance.canonicalize("&#x003c;"))
        self.assertEquals( "<", instance.canonicalize("&#x0003c;"))
        self.assertEquals( "<", instance.canonicalize("&#x00003c;"))
        self.assertEquals( "<", instance.canonicalize("&#x000003c;"))
        self.assertEquals( "<", instance.canonicalize("&#X3c"))
        self.assertEquals( "<", instance.canonicalize("&#X03c"))
        self.assertEquals( "<", instance.canonicalize("&#X003c"))
        self.assertEquals( "<", instance.canonicalize("&#X0003c"))
        self.assertEquals( "<", instance.canonicalize("&#X00003c"))
        self.assertEquals( "<", instance.canonicalize("&#X000003c"))
        self.assertEquals( "<", instance.canonicalize("&#X3c;"))
        self.assertEquals( "<", instance.canonicalize("&#X03c;"))
        self.assertEquals( "<", instance.canonicalize("&#X003c;"))
        self.assertEquals( "<", instance.canonicalize("&#X0003c;"))
        self.assertEquals( "<", instance.canonicalize("&#X00003c;"))
        self.assertEquals( "<", instance.canonicalize("&#X000003c;"))
        self.assertEquals( "<", instance.canonicalize("&#x3C"))
        self.assertEquals( "<", instance.canonicalize("&#x03C"))
        self.assertEquals( "<", instance.canonicalize("&#x003C"))
        self.assertEquals( "<", instance.canonicalize("&#x0003C"))
        self.assertEquals( "<", instance.canonicalize("&#x00003C"))
        self.assertEquals( "<", instance.canonicalize("&#x000003C"))
        self.assertEquals( "<", instance.canonicalize("&#x3C;"))
        self.assertEquals( "<", instance.canonicalize("&#x03C;"))
        self.assertEquals( "<", instance.canonicalize("&#x003C;"))
        self.assertEquals( "<", instance.canonicalize("&#x0003C;"))
        self.assertEquals( "<", instance.canonicalize("&#x00003C;"))
        self.assertEquals( "<", instance.canonicalize("&#x000003C;"))
        self.assertEquals( "<", instance.canonicalize("&#X3C"))
        self.assertEquals( "<", instance.canonicalize("&#X03C"))
        self.assertEquals( "<", instance.canonicalize("&#X003C"))
        self.assertEquals( "<", instance.canonicalize("&#X0003C"))
        self.assertEquals( "<", instance.canonicalize("&#X00003C"))
        self.assertEquals( "<", instance.canonicalize("&#X000003C"))
        self.assertEquals( "<", instance.canonicalize("&#X3C;"))
        self.assertEquals( "<", instance.canonicalize("&#X03C;"))
        self.assertEquals( "<", instance.canonicalize("&#X003C;"))
        self.assertEquals( "<", instance.canonicalize("&#X0003C;"))
        self.assertEquals( "<", instance.canonicalize("&#X00003C;"))
        self.assertEquals( "<", instance.canonicalize("&#X000003C;"))
        self.assertEquals( "<", instance.canonicalize("&lt"))
        self.assertEquals( "<", instance.canonicalize("&lT"))
        self.assertEquals( "<", instance.canonicalize("&Lt"))
        self.assertEquals( "<", instance.canonicalize("&LT"))
        self.assertEquals( "<", instance.canonicalize("&lt;"))
        self.assertEquals( "<", instance.canonicalize("&lT;"))
        self.assertEquals( "<", instance.canonicalize("&Lt;"))
        self.assertEquals( "<", instance.canonicalize("&LT;"))
        
        self.assertEquals( "<script>alert(\"hello\");</script>", instance.canonicalize("%3Cscript%3Ealert%28%22hello%22%29%3B%3C%2Fscript%3E") )
        self.assertEquals( "<script>alert(\"hello\");</script>", instance.canonicalize("%3Cscript&#x3E;alert%28%22hello&#34%29%3B%3C%2Fscript%3E", False) )
        
        # javascript escape syntax
        js = [JavascriptCodec()]
        instance = encoder_class( js )

        self.assertEquals( "\0", instance.canonicalize("\\0"))
        self.assertEquals( "\b", instance.canonicalize("\\b"))
        self.assertEquals( "\t", instance.canonicalize("\\t"))
        self.assertEquals( "\n", instance.canonicalize("\\n"))
        self.assertEquals( unichr(0x0b), instance.canonicalize("\\v"))
        self.assertEquals( "\f", instance.canonicalize("\\f"))
        self.assertEquals( "\r", instance.canonicalize("\\r"))
        self.assertEquals( "\'", instance.canonicalize("\\'"))
        self.assertEquals( "\"", instance.canonicalize("\\\""))
        self.assertEquals( "\\", instance.canonicalize("\\\\"))
        self.assertEquals( "<", instance.canonicalize("\\<"))
        
        self.assertEquals( "<", instance.canonicalize("\\u003c"))
        self.assertEquals( "<", instance.canonicalize("\\U003c"))
        self.assertEquals( "<", instance.canonicalize("\\u003C"))
        self.assertEquals( "<", instance.canonicalize("\\U003C"))
        self.assertEquals( "<", instance.canonicalize("\\x3c"))
        self.assertEquals( "<", instance.canonicalize("\\X3c"))
        self.assertEquals( "<", instance.canonicalize("\\x3C"))
        self.assertEquals( "<", instance.canonicalize("\\X3C"))

        # css escape syntax
        # be careful because some codecs see \0 as null byte
        css = [CSSCodec()]
        instance = encoder_class( css )
        self.assertEquals( "<", instance.canonicalize("\\3c"));  # add strings to prevent null byte
        self.assertEquals( "<", instance.canonicalize("\\03c"))
        self.assertEquals( "<", instance.canonicalize("\\003c"))
        self.assertEquals( "<", instance.canonicalize("\\0003c"))
        self.assertEquals( "<", instance.canonicalize("\\00003c"))
        self.assertEquals( "<", instance.canonicalize("\\3C"))
        self.assertEquals( "<", instance.canonicalize("\\03C"))
        self.assertEquals( "<", instance.canonicalize("\\003C"))
        self.assertEquals( "<", instance.canonicalize("\\0003C"))
        self.assertEquals( "<", instance.canonicalize("\\00003C"))
     
    def test_double_encoding_canonicalization(self):
        instance = ESAPI.encoder()
        
        # note these examples use the strict=False flag on canonicalize to allow
        # full decoding without throwing an IntrusionException. Generally, you
        # should use strict mode as allowing double-encoding is an abomination.
        
        # double encoding examples
        self.assertEquals( "<", instance.canonicalize("&#x26;lt&#59", False )); #double entity
        self.assertEquals( "\\", instance.canonicalize("%255c", False)); #double percent
        self.assertEquals( "%", instance.canonicalize("%2525", False)); #double percent
        
        # double encoding with multiple schemes example
        self.assertEquals( "<", instance.canonicalize("%26lt%3b", False)); #first entity, then percent
        self.assertEquals( "&", instance.canonicalize("&#x25;26", False)); #first percent, then entity
          
        # nested encoding examples
        self.assertEquals( "<", instance.canonicalize("%253c", False)); #nested encode % with percent
        self.assertEquals( "<", instance.canonicalize("%%33%63", False)); #nested encode both nibbles with percent
        self.assertEquals( "<", instance.canonicalize("%%33c", False)); # nested encode first nibble with percent
        self.assertEquals( "<", instance.canonicalize("%3%63", False));  #nested encode second nibble with percent
        self.assertEquals( "<", instance.canonicalize("&&#108;t;", False)); #nested encode l with entity
        self.assertEquals( "<", instance.canonicalize("%2&#x35;3c", False)); #triple percent, percent, 5 with entity
        
        # nested encoding with multiple schemes examples
        self.assertEquals( "<", instance.canonicalize("&%6ct;", False)); # nested encode l with percent
        self.assertEquals( "<", instance.canonicalize("%&#x33;c", False)); #nested encode 3 with entity            
        
        # multiple encoding tests
        self.assertEquals( "% & <script> <script>", instance.canonicalize( "%25 %2526 %26#X3c;script&#x3e; &#37;3Cscript%25252525253e", False ) )
        self.assertEquals( "< < < < < < <", instance.canonicalize( "%26lt; %26lt; &#X25;3c &#x25;3c %2526lt%253B %2526lt%253B %2526lt%253B", False ) )

        # test strict mode with both mixed and multiple encoding
        self.assertRaises( IntrusionException, instance.canonicalize, "%26lt; %26lt; &#X25;3c &#x25;3c %2526lt%253B %2526lt%253B %2526lt%253B" )
        self.assertRaises( IntrusionException, instance.canonicalize, "%253Cscript" ) 
        self.assertRaises( IntrusionException, instance.canonicalize, "&#37;3Cscript" )
            
    def test_html_codec(self):
        instance = ESAPI.encoder()
        
        ### High level
        
        self.assertEquals(None, instance.encode_for_html(None))
        # test invalid characters are replaced with spaces
        self.assertEquals("a b c d e f&#x9;g", instance.encode_for_html("a" + unichr(0) + "b" + unichr(4) + "c" + unichr(128) + "d" + unichr(150) + "e" +unichr(159) + "f" + unichr(9) + "g"))
        
        self.assertEquals("&lt;script&gt;", instance.encode_for_html("<script>"))
        self.assertEquals("&amp;lt&#x3b;script&amp;gt&#x3b;", instance.encode_for_html("&lt;script&gt;"))
        self.assertEquals("&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;", instance.encode_for_html("!@$%()=+{}[]"))

        self.assertEquals(",.-_ ", instance.encode_for_html(",.-_ "))
        self.assertEquals("dir&amp;", instance.encode_for_html("dir&"))
        self.assertEquals("one&amp;two", instance.encode_for_html("one&two"))
        # Unicode
        self.assertEquals(unichr(12345), instance.encode_for_html(unichr(12345)))
        
        ### Low lovel
        codec = HTMLEntityCodec()
        
        cases = (
                 # PLAIN - ENCODED - ALT_ENCODINGS
                 ('', '', ()),
                 ('t','t', ()),
                 ('test', 'test', ()),
                 ('<script>', '&lt;script&gt;', ()),
                 ('!@#$%^&*(){}[]?+/=|\\', '&#x21;&#x40;&#x23;&#x24;&#x25;&#x5e;&amp;&#x2a;&#x28;&#x29;&#x7b;&#x7d;&#x5b;&#x5d;&#x3f;&#x2b;&#x2f;&#x3d;&#x7c;&#x5c;', ()),
                 ('"`~1234_-', '&quot;&#x60;&#x7e;1234&#x5f;&#x2d;', ()),
                 (unichr(9), "&#x9;", ()),
                 (unichr(12345), unichr(12345), ()),
                 ('\\', '&#x5c;', ()),
             )
             
        for case in cases:
            self.assertEquals(case[ENCODED], codec.encode('', case[PLAIN]))
            self.assertEquals(case[PLAIN], codec.decode(case[ENCODED]))
            for encoding in case[ALT_ENCODINGS]:
                self.assertEquals(case[PLAIN], codec.decode(encoding))
        
        # Bad entity name
        self.assertEquals("&ridiculous;", codec.decode("&ridiculous;"))
        
        
    def test_encode_for_html_attribute(self):
        instance = ESAPI.encoder()
        
        self.assertEquals(None, instance.encode_for_html_attribute(None))
        self.assertEquals("&lt;script&gt;", instance.encode_for_html_attribute("<script>"))
        self.assertEquals(",.-_", instance.encode_for_html_attribute(",.-_"))
        self.assertEquals("&#x20;&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;", instance.encode_for_html_attribute(" !@$%()=+{}[]"))
        
    def test_codec_for_css(self):
        instance = ESAPI.encoder()
       
        ### High level
        self.assertEquals(None, instance.encode_for_css(None))
        self.assertEquals("\\3c script\\3e ", instance.encode_for_css("<script>"))
        self.assertEquals("\\21 \\40 \\24 \\25 \\28 \\29 \\3d \\2b \\7b \\7d \\5b \\5d ", instance.encode_for_css("!@$%()=+{}[]"))
        # Unicode
        self.assertEquals(unichr(12345), instance.encode_for_css(unichr(12345)))
        
        ### Low level
        codec = CSSCodec()
        
        cases = (
             # PLAIN - ENCODED - ALT_ENCODINGS
             ('', '', ()), # 0 length string
             ('t','t', ()),
             ('test', 'test', ()),
             ('<script>', '\\3c script\\3e ', ()),
             ('!@#$%^&*(){}[]?+/=|\\', '\\21 \\40 \\23 \\24 \\25 \\5e \\26 \\2a \\28 \\29 \\7b \\7d \\5b \\5d \\3f \\2b \\2f \\3d \\7c \\5c ', ()),
             ('"`~1234_-', '\\22 \\60 \\7e 1234\\5f \\2d ', ()),
             (unichr(9), "\\9 ", ()),
             (unichr(12345), unichr(12345), ()),
             ('\\', '\\5c ', ('\\')),
             ('\\2aq', None, ("\\2aq",)), # Malformed hex
             ('\\2aq ', None, ("\\2aq ",)), # Malformed hex
             ('\\q ', None, ('\\q ',)), # Malformed hex
         )
             
        for case in cases:
            if case[ENCODED] is not None:
                self.assertEquals(case[ENCODED], codec.encode('', case[PLAIN]))
                self.assertEquals(case[PLAIN], codec.decode(case[ENCODED]))
            for encoding in case[ALT_ENCODINGS]:
                print "encoding=",encoding
                self.assertEquals(case[PLAIN], codec.decode(encoding))
                           
    def test_codec_for_javascript(self):
        instance = ESAPI.encoder()
        
        ### High level
        self.assertEquals(None, instance.encode_for_javascript(None))
        self.assertEquals("\\x3Cscript\\x3E", instance.encode_for_javascript("<script>"))
        self.assertEquals(",.\\x2D_\\x20", instance.encode_for_javascript(",.-_ "))
        self.assertEquals("\\x21\\x40\\x24\\x25\\x28\\x29\\x3D\\x2B\\x7B\\x7D\\x5B\\x5D", instance.encode_for_javascript("!@$%()=+{}[]"))
        
        #   Unicode
        self.assertEquals(unichr(12345), instance.encode_for_javascript(unichr(12345)))
        
        ### Low level
        codec = JavascriptCodec()
        
        # Bad hex format
        self.assertEquals("\\xAQ", codec.decode("\\xAQ"))
        self.assertEquals("\\uAAQ", codec.decode("\\uAAQ"))
        
    
    def test_codec_for_vbscript(self):
        instance = ESAPI.encoder()
        
        ### High level
        self.assertEquals(None, instance.encode_for_vbscript(None))
        self.assertEquals( "chrw(60)&\"script\"&chrw(62)", instance.encode_for_vbscript("<script>"))
        self.assertEquals( "x\"&chrw(32)&chrw(33)&chrw(64)&chrw(36)&chrw(37)&chrw(40)&chrw(41)&chrw(61)&chrw(43)&chrw(123)&chrw(125)&chrw(91)&chrw(93)", instance.encode_for_vbscript("x !@$%()=+{}[]"))
        self.assertEquals( "alert\"&chrw(40)&chrw(39)&\"ESAPI\"&chrw(32)&\"test\"&chrw(33)&chrw(39)&chrw(41)", instance.encode_for_vbscript("alert('ESAPI test!')" ))
        self.assertEquals( "jeff.williams\"&chrw(64)&\"aspectsecurity.com", instance.encode_for_vbscript("jeff.williams@aspectsecurity.com"))
        self.assertEquals( "test\"&chrw(32)&chrw(60)&chrw(62)&chrw(32)&\"test", instance.encode_for_vbscript("test <> test" ))
        
        ### Low level
        codec = VBScriptCodec()

        cases = (
             # PLAIN - ENCODED - ALT_ENCODINGS
             ('', '', ()), # 0 length string
             ('t','t', ()),
             ('test', 'test', ()),
             (unichr(12345), unichr(12345), ()),
         )
             
        for case in cases:
            if case[ENCODED] is not None:
                self.assertEquals(case[ENCODED], codec.encode('', case[PLAIN]))
                self.assertEquals(case[PLAIN], codec.decode(case[ENCODED]))
            for encoding in case[ALT_ENCODINGS]:
                print "encoding=",encoding
                self.assertEquals(case[PLAIN], codec.decode(encoding))
                
        encode_only_cases = (
             # PLAIN - ENCODED - ALT_ENCODINGS
             ('<script>', 'chrw(60)&"script"&chrw(62)', ()),
             ('!@#$%^&*(){}[]?+/=|\\', 'chrw(33)&chrw(64)&chrw(35)&chrw(36)&chrw(37)&chrw(94)&chrw(38)&chrw(42)&chrw(40)&chrw(41)&chrw(123)&chrw(125)&chrw(91)&chrw(93)&chrw(63)&chrw(43)&chrw(47)&chrw(61)&chrw(124)&chrw(92)', ()),
             ('"`~1234_-', 'chrw(34)&chrw(96)&chrw(126)&"1234"&chrw(95)&chrw(45)', ()),
             (unichr(9), "chrw(9)", ()),
             ('\\', 'chrw(92)', ('\\')),
         )
         
        for case in encode_only_cases:
            if case[ENCODED] is not None:
                self.assertEquals(case[ENCODED], codec.encode('', case[PLAIN]))
    
    def test_encode_for_xpath(self):
        instance = ESAPI.encoder()
        self.assertEquals(None, instance.encode_for_xpath(None))
        self.assertEquals("&#x27;or 1&#x3d;1", instance.encode_for_xpath("'or 1=1"))
        
    def test_sql_codec(self):
        instance = ESAPI.encoder()

        ### High level
        mySQL1 = MySQLCodec( MySQLCodec.ANSI_MODE )
        self.assertEquals(None, instance.encode_for_sql(mySQL1, None))
        self.assertEquals("Jeff'' or ''1''=''1", instance.encode_for_sql(mySQL1, "Jeff' or '1'='1"))
        self.assertEquals("''", instance.encode_for_sql(mySQL1, "'"))
        self.assertEquals(unichr(12345), instance.encode_for_sql(mySQL1, unichr(12345)))
        
        mySQL2 = MySQLCodec( MySQLCodec.MYSQL_MODE )
        self.assertEquals(None, instance.encode_for_sql(mySQL2, None))
        self.assertEquals("Jeff\\' or \\'1\\'\\=\\'1", instance.encode_for_sql(mySQL2, "Jeff' or '1'='1"))
        self.assertEquals("\\t", instance.encode_for_sql(mySQL2, unichr(9)))
        self.assertEquals(unichr(12345), instance.encode_for_sql(mySQL2, unichr(12345)))
    
        ### Low level
        cases = ('test',
                 '<script>',
                 'the answer',
                 '!@#$%^&*(){}[]?+/=|\\',
                 '"`~1234_-',
                 unichr(9),
                 unichr(12345))
                 
        for case in cases:
            self.assertEquals(case, mySQL1.decode(mySQL1.encode('', case)))
            self.assertEquals(case, mySQL2.decode(mySQL1.encode('', case)))
            
        self.assertEquals(unichr(9), mySQL2.decode("\\t"))
        self.assertEquals('m', mySQL2.decode("\\m"))
        
        self.assertEquals("'", mySQL1.decode("''"))
        self.assertEquals("'", mySQL1.decode("'"))
        self.assertEquals("'q", mySQL1.decode("'q"))
        
        # Bad mode
        self.assertRaises(BadModeError, MySQLCodec, -2 )
        
    
    def test_oracle_codec(self):
        instance = ESAPI.encoder()
        ### High level
        oracle = OracleCodec()
        self.assertEquals(None, instance.encode_for_sql(oracle, None))
        self.assertEquals("''", instance.encode_for_sql(oracle, "'"))
        
        
        ### Low level
        cases = ('t',
                 'test',
                 '<script>',
                 'the answer',
                 '!@#$%^&*(){}[]?+/=|\\',
                 '"`~1234_-',
                 unichr(9),
                 unichr(12345),
                 '\\')
                 
        for case in cases:
            self.assertEquals(case, oracle.decode(oracle.encode('', case)))
            
        self.assertEquals("''", oracle.encode('', "'"))
        self.assertEquals("'", oracle.decode("''"))
    
    def test_encode_for_ldap(self):
        instance = ESAPI.encoder()
        self.assertEquals(None, instance.encode_for_ldap(None))
        self.assertEquals("Hi This is a test #ï¿½ï¿½", instance.encode_for_ldap("Hi This is a test #ï¿½ï¿½") ,"No special characters to escape")
        self.assertEquals("Hi \\00", instance.encode_for_ldap("Hi " + unichr(0)), "Zeros")
        self.assertEquals("Hi \\28This\\29 = is \\2a a \\5c test # ï¿½ ï¿½ ï¿½", instance.encode_for_ldap("Hi (This) = is * a \\ test # ï¿½ ï¿½ ï¿½"), "LDAP Christams Tree")
    
    def test_encode_for_dn(self):
        instance = ESAPI.encoder()
        self.assertEquals(None, instance.encode_for_dn(None))
        self.assertEquals("Helloï¿½", instance.encode_for_dn("Helloï¿½"), "No special characters to escape")
        self.assertEquals("\\# Helloï¿½", instance.encode_for_dn("# Helloï¿½"), "leading #")
        self.assertEquals("\\ Helloï¿½", instance.encode_for_dn(" Helloï¿½"), "leading space")
        self.assertEquals("Helloï¿½\\ ", instance.encode_for_dn("Helloï¿½ "), "trailing space")
        self.assertEquals("Hello\\<\\>", instance.encode_for_dn("Hello<>"), "less than greater than")
        self.assertEquals("\\  \\ ", instance.encode_for_dn("   "), "only 3 spaces")
        self.assertEquals("\\ Hello\\\\ \\+ \\, \\\"World\\\" \\;\\ ", instance.encode_for_dn(" Hello\\ + , \"World\" ; "), "Christmas Tree DN")
    
    def test_encode_for_xml(self):
        instance = ESAPI.encoder()
        self.assertEquals(None, instance.encode_for_xml(None))
        self.assertEquals(" ", instance.encode_for_xml(" "))
        self.assertEquals("&lt;script&gt;", instance.encode_for_xml("<script>"))
        self.assertEquals(",.-_", instance.encode_for_xml(",.-_"))
        self.assertEquals("&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;", instance.encode_for_xml("!@$%()=+{}[]"))
    
    def test_encode_for_xml_attribute(self):
        instance = ESAPI.encoder()
        self.assertEquals(None, instance.encode_for_xml_attribute(None))
        self.assertEquals("&#x20;", instance.encode_for_xml_attribute(" "))
        self.assertEquals("&lt;script&gt;", instance.encode_for_xml_attribute("<script>"))
        self.assertEquals(",.-_", instance.encode_for_xml_attribute(",.-_"))
        self.assertEquals("&#x20;&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;", instance.encode_for_xml_attribute(" !@$%()=+{}[]"))
    
    def test_percent_codec(self):
        instance = ESAPI.encoder()
        
        ### High level
        self.assertEquals(None, instance.encode_for_url(None))
        self.assertEquals("%3Cscript%3E", instance.encode_for_url("<script>"))
        self.assertEquals("%03", instance.encode_for_url(unichr(3)))
        self.assertEquals("+", instance.encode_for_url(" "))
        self.assertEquals(unichr(12345), instance.encode_for_url(unichr(12345)))
        
        self.assertEquals(None, instance.decode_from_url(None))
        self.assertEquals("<script>", instance.decode_from_url("%3Cscript%3E"))
        self.assertEquals(unichr(3), instance.decode_from_url("%03"))
        self.assertEquals("     ", instance.decode_from_url("+++++") )
        self.assertEquals(unichr(12345), instance.decode_from_url(unichr(12345)))

        # Wrap in assertRaises
        self.assertEquals("%3xridiculous", instance.decode_from_url( "%3xridiculous" ))

        ### Low level
        

    def test_encode_for_base64(self):
        instance = ESAPI.encoder()
        
        self.assertEquals(None, instance.encode_for_base64(None))
        self.assertEquals(None, instance.decode_from_base64(None))
        for i in range(100):
            random_string = ESAPI.randomizer().get_random_string( 20, Encoder.CHAR_SPECIALS )
            encoded = instance.encode_for_base64( random_string )
            decoded = instance.decode_from_base64( encoded )
            self.assertEquals( random_string, decoded )
    
    def test_decode_from_base64(self):
        instance = ESAPI.encoder()
        for i in range(100):
            random_string = ESAPI.randomizer().get_random_string( 20, Encoder.CHAR_SPECIALS )
            encoded = instance.encode_for_base64( random_string )
            decoded = instance.decode_from_base64( encoded )
            self.assertEqual( random_string, decoded )

        for i in range(100):
            random_string = ESAPI.randomizer().get_random_string( 20, Encoder.CHAR_SPECIALS )
            encoded = ESAPI.randomizer().get_random_string(1, Encoder.CHAR_ALPHANUMERICS) + instance.encode_for_base64( random_string )
            decoded = instance.decode_from_base64( encoded )
            self.assertFalse( random_string == decoded )

    def test_windows_codec(self):
        instance = ESAPI.encoder()

        win = WindowsCodec()
        immune = []
        self.assertEquals(None, instance.encode_for_os(win, None))
        
        npbs = PushbackString("n")
        self.assertEquals(None, win.decode_character(npbs))

        epbs = PushbackString("")
        self.assertEquals(None, win.decode_character(epbs))
        
        c = '<'
        cpbs = PushbackString(win.encode_character(immune, c))
        decoded = win.decode_character(cpbs)
        self.assertEquals(c, decoded)
        
        orig = "c:\\jeff"
        enc = win.encode(Encoder.CHAR_ALPHANUMERICS, orig)
        self.assertEquals(orig, win.decode(enc))
        self.assertEquals(orig, win.decode(orig))
       
        self.assertEquals("c^:^\\jeff", instance.encode_for_os(win, "c:\\jeff"));		
        self.assertEquals("c^:^\\jeff", win.encode(immune, "c:\\jeff"))
        self.assertEquals("dir^ ^&^ foo", instance.encode_for_os(win, "dir & foo"))
        self.assertEquals("dir^ ^&^ foo", win.encode(immune, "dir & foo"))
    
    def test_unix_codec(self):
        instance = ESAPI.encoder()

        unix = UnixCodec()
        immune = ''
        self.assertEquals(None, instance.encode_for_os(unix, None))
        
        npbs = PushbackString("n")
        self.assertEquals(None, unix.decode_character(npbs))

        c = '<'
        cpbs = PushbackString(unix.encode_character(immune, c))
        decoded = unix.decode_character(cpbs)
        self.assertEquals(c, decoded)
        
        epbs = PushbackString("")
        self.assertEquals(None, unix.decode_character(epbs))

        orig = "/etc/passwd"
        enc = unix.encode(immune, orig)
        self.assertEquals(orig, unix.decode(enc))
        self.assertEquals(orig, unix.decode(orig))
        
        self.assertEquals("c\\:\\\\jeff", instance.encode_for_os(unix, "c:\\jeff"))
        self.assertEquals("c\\:\\\\jeff", unix.encode(immune, "c:\\jeff"))
        self.assertEquals("dir\\ \\&\\ foo", instance.encode_for_os(unix, "dir & foo"))
        self.assertEquals("dir\\ \\&\\ foo", unix.encode(immune, "dir & foo"))

        # Unix paths (that must be encoded safely)
        self.assertEquals("\\/etc\\/hosts", instance.encode_for_os(unix, "/etc/hosts"))
        self.assertEquals("\\/etc\\/hosts\\;\\ ls\\ -l", instance.encode_for_os(unix, "/etc/hosts; ls -l"))
        
        self.assertEquals("\\", unix.decode('\\'))
        self.assertEquals(unichr(12345), unix.encode('', unichr(12345)))
        
        
            
#    def test_concurrency(self):
#        class EncoderConcurrencyMock(threading.Thread):
#            def __init__(self, num):
#                threading.Thread.__init__(self)
#                self.num = num
#                
#            def run(self):
#                for i in range(20):
#                    nonce = ESAPI.randomizer().get_random_string(
#                        20, 
#                        Encoder.CHAR_SPECIALS )
#                    result = self.javascript_encode( nonce )
#                    # randomize the threads
#                    time.sleep( ESAPI.randomizer().get_random_integer( 100, 500 ) / 1000.0 )
#                    assert result == self.javascript_encode( nonce )
#                    
#            def javascript_encode(self, string):
#                encoder = ESAPI.security_configuration().get_class_for_interface('encoder')()
#                return encoder.encode_for_javascript(string)
    
#        threads = []
#        for i in range(5):
#            threads.append(EncoderConcurrencyMock(i))
            
#        # start
#        for thread in threads:
#            thread.start()
            
#        # join
#        for thread in threads:
#            thread.join()

if __name__ == "__main__":
    unittest.main()
