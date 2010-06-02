#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: The Encoder interface contains a number of methods for decoding 
    input and encoding output so that it will be safe for a variety of 
    interpreters.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

class Encoder():
    """
    The Encoder interface contains a number of methods for decoding input and encoding output
    so that it will be safe for a variety of interpreters. To prevent
    double-encoding, callers should make sure input does not already contain encoded characters
    by calling canonicalize. Validator implementations should call canonicalize on user input
    B{before} validating to prevent encoded attacks.

    All of the methods must use a "whitelist" or "positive" security model.
    For the encoding methods, this means that all characters should be encoded, except for a specific list of
    "immune" characters that are known to be safe.

    The Encoder performs two key functions, encoding and decoding. These functions rely
    on a set of codecs that can be found in the org.owasp.esapi.codecs package. These include:
        - CSS Escaping
        - HTMLEntity Encoding
        - JavaScript Escaping
        - MySQL Escaping
        - Oracle Escaping
        - Percent Encoding (aka URL Encoding)
        - Unix Escaping
        - VBScript Escaping
        - Windows Encoding

    @author: Craig Younkins (craig.younkins@owasp.org)
    """
    
    # Standard character sets
    CHAR_LOWERS = 'abcdefghijklmnopqrstuvwxyz'
    CHAR_UPPERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    CHAR_DIGITS = '0123456789'
    CHAR_SPECIALS = '.-_!@$^*=~|+?'
    CHAR_LETTERS = CHAR_LOWERS + CHAR_UPPERS
    CHAR_ALPHANUMERICS = CHAR_LETTERS + CHAR_DIGITS
    CHAR_LOWER_HEX = CHAR_DIGITS + 'abcdef'
    CHAR_UPPER_HEX = CHAR_DIGITS + 'ABCDEF'
    
    """
    Password character set, is alphanumerics (without l, i, I, o, O, and 0)
    selected specials like + (bad for URL encoding, | is like i and 1,
    etc...)
    """
    CHAR_PASSWORD_LOWERS = 'abcdefghjkmnpqrstuvwxyz'
    CHAR_PASSWORD_UPPERS = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
    CHAR_PASSWORD_DIGITS = '23456789'
    CHAR_PASSWORD_SPECIALS = '_.!@$*=-?'
    CHAR_PASSWORD_LETTERS = CHAR_PASSWORD_LOWERS + CHAR_PASSWORD_UPPERS
    CHAR_PASSWORD_ALL = CHAR_PASSWORD_LETTERS + CHAR_PASSWORD_DIGITS + CHAR_PASSWORD_SPECIALS
    
    def __init__(self):
        pass

    def canonicalize(self, input_, strict=True):
        """
        Canonicalization is simply the operation of reducing a possibly encoded
        string down to its simplest form. This is important, because attackers
        frequently use encoding to change their input in a way that will bypass
        validation filters, but still be interpreted properly by the target of
        the attack. Note that data encoded more than once is not something that a
        normal user would generate and should be regarded as an attack.

        Everyone U{says<http://cwe.mitre.org/data/definitions/180.html>} you shouldn't do validation
        without canonicalizing the data first. This is easier said than done. The canonicalize method can
        be used to simplify just about any input down to its most basic form. Note that canonicalize doesn't
        handle Unicode issues, it focuses on higher level encoding and escaping schemes. In addition to simple
        decoding, canonicalize also handles:
            - Perverse but legal variants of escaping schemes
            - Multiple escaping (%2526 or &#x26;lt;)
            - Mixed escaping (%26lt;)
            - Nested escaping (%%316 or &%6ct;)
            - All combinations of multiple, mixed, and nested encoding/escaping (%2&#x35;3c or &#x2526gt;)

        Using canonicalize is simple. The default is just...
            
            >>> clean = ESAPI.encoder().canonicalize( request.getParameter("input"))
            
        You need to decode untrusted data so that it's safe for ANY downstream interpreter or decoder. For
        example, if your data goes into a Windows command shell, then into a database, and then to a browser,
        you're going to need to decode for all of those systems. You can build a custom encoder to canonicalize
        for your application like this...
       
            >>> codeclist = [WindowsCodec(), MySQLCodec(), PercentCodec()]
            >>> encoder = DefaultEncoder( codeclist )
            >>> clean = encoder.canonicalize( request.getParameter( "input" ))

        In ESAPI, the Validator uses the canonicalize method before it does validation.  So all you need to
        do is to validate as normal and you'll be protected against a host of encoded attacks.

            >>> input = request.getParameter( "name" )
            >>> name = ESAPI.validator().is_valid_input( "test", input, "FirstName", 20, False)

        However, the default canonicalize() method only decodes HTMLEntity, percent (URL) encoding, and JavaScript
        encoding. If you'd like to use a custom canonicalizer with your validator, that's pretty easy too.

            >>> #... setup custom encoder as above
            >>> validator = DefaultValidator( encoder )
            >>> input = request.getParameter( "name" )
            >>> name = validator.is_valid_input( "test", input, "name", 20, False)

        Although ESAPI is able to canonicalize multiple, mixed, or nested encoding, it's safer to not accept
        this stuff in the first place. In ESAPI, the default is "strict" mode that throws an IntrusionException
        if it receives anything not single-encoded with a single scheme.  Currently this is not configurable
        in ESAPI.properties, but it probably should be.  Even if you disable "strict" mode, you'll still get
        warning messages in the log about each multiple encoding and mixed encoding received.

            >>> # disabling strict mode to allow mixed encoding
            >>> url = ESAPI.encoder().canonicalize( request.getParameter("url"), False)

        @see: U{W3C specifications<http://www.w3.org/TR/html4/interact/forms.html#h-17.13.4>}

        @param input_: the text to canonicalize
        @param strict: true (default) if checking for double encoding is 
            desired, false otherwise

        @return: a string containing the canonicalized text

        @raises EncodingException: if canonicalization fails
        """
        raise NotImplementedError()

    def encode_for_css(self, input_):
        """
        Encode data for use in Cascading Style Sheets (CSS) content.

        @see: U{CSS Syntax [w3.org]<http://www.w3.org/TR/CSS21/syndata.html#escaped-characters>}

        @param input_: the text to encode for CSS

        @return: input encoded for CSS
        """
        raise NotImplementedError()

    def encode_for_html(self, input_):
        """
        Encode data for use in HTML using HTML entity encoding
        
        Note that the following characters:
        00-08, 0B-0C, 0E-1F, and 7F-9F
        cannot be used in HTML.

        @see: U{HTML Encodings [wikipedia.org]<http://en.wikipedia.org/wiki/Character_encodings_in_HTML>}
        @see: U{SGML Specification [w3.org]<http://www.w3.org/TR/html4/sgml/sgmldecl.html>}
        @see: U{XML Specification [w3.org]<http://www.w3.org/TR/REC-xml/#charsets>}

        @param input_: the text to encode for HTML

        @return: input encoded for HTML
        """
        raise NotImplementedError()

    def encode_for_html_attribute(self, input_):
        """
        Encode data for use in HTML attributes.

        @param input_: the text to encode for an HTML attribute

        @return: input encoded for use as an HTML attribute
        """
        raise NotImplementedError()

    def encode_for_javascript(self, input_):
        """
        Encode data for insertion inside a data value in JavaScript. Putting user data directly
        inside a script is quite dangerous. Great care must be taken to prevent putting user data
        directly into script code itself, as no amount of encoding will prevent attacks there.

        @param input_: the text to encode for JavaScript

        @return: input encoded for use in JavaScript
        """
        raise NotImplementedError()

    def encode_for_vbscript(self, input_):
        """
        Encode data for insertion inside a data value in a Visual Basic script. Putting user data directly
        inside a script is quite dangerous. Great care must be taken to prevent putting user data
        directly into script code itself, as no amount of encoding will prevent attacks there.

        This method is not recommended as VBScript is only supported by Internet Explorer

        @param input_: the text to encode for VBScript

        @return: input encoded for use in VBScript
        """
        raise NotImplementedError()

    def encode_for_sql(self, codec, input_):
        """
        Encode input for use in a SQL query, according to the selected codec
        (appropriate codecs include the MySQLCodec and OracleCodec).

        This method is not recommended. The use of the PreparedStatement
        interface is the preferred approach. However, if for some reason
        this is impossible, then this method is provided as a weaker
        alternative.

        The best approach is to make sure any single-quotes are double-quoted.
        Another possible approach is to use the {escape} syntax described in the
        JDBC specification in section 1.5.6.

        However, this syntax does not work with all drivers, and requires
        modification of all queries.

        @see: U{JDBC Specification<http://java.sun.com/j2se/1.4.2/docs/guide/jdbc/getstart/statement.html>}

        @param codec: a Codec that declares which database 'input' is being encoded for (ie. MySQL, Oracle, etc.)
        @param input_: the text to encode for SQL

        @return: input encoded for use in SQL
        """
        raise NotImplementedError()

    def encode_for_os(self, codec, input_):
        """
        Encode for an operating system command shell according to the selected codec (appropriate codecs include
        the WindowsCodec and UnixCodec).

        @param codec: a Codec that declares which operating system 'input' is being encoded for (ie. Windows, Unix, etc.)
        @param input_: the text to encode for the command shell

        @return: input encoded for use in command shell
        """
        raise NotImplementedError()

    def encode_for_ldap(self, input_):
        """
        Encode data for use in LDAP queries.

        @param input_: the text to encode for LDAP

        @return: input encoded for use in LDAP
        """
        raise NotImplementedError()

    def encode_for_dn(self, input_):
        """
        Encode data for use in an LDAP distinguished name.

        @param input_: the text to encode for an LDAP distinguished name

        @return: input encoded for use in an LDAP distinguished name
        """
        raise NotImplementedError()

    def encode_for_xpath(self, input_):
        """
        Encode data for use in an XPath query.

        NB: The reference implementation encodes almost everything and may over-encode.

        The difficulty with XPath encoding is that XPath has no built in mechanism for escaping
        characters. It is possible to use XQuery in a parameterized way to
        prevent injection.

        For more information, refer to U{this article<http://www.ibm.com/developerworks/xml/library/x-xpathinjection.html>}
        which specifies the following list of characters as the most
        dangerous: ^&"*';<>(). U{This paper<http://www.packetstormsecurity.org/papers/bypass/Blind_XPath_Injection_20040518.pdf>}
        suggests disallowing ' and " in queries.

        @see: U{XPath Injection [ibm.com]<http://www.ibm.com/developerworks/xml/library/x-xpathinjection.html>}
        @see: U{Blind XPath Injection [packetstormsecurity.org]<http://www.packetstormsecurity.org/papers/bypass/Blind_XPath_Injection_20040518.pdf>}

        @param input_: the text to encode for XPath
        
        @return: input encoded for use in XPath
        """
        raise NotImplementedError()

    def encode_for_xml(self, input_):
        """
        Encode data for use in an XML element. The implementation should follow the 
        U{XML Encoding Standard<http://www.w3schools.com/xml/xml_encoding.asp>}
        from the W3C.
        
        The use of a real XML parser is strongly encouraged. However, in the
        hopefully rare case that you need to make sure that data is safe for
        inclusion in an XML document and cannot use a parse, this method provides
        a safe mechanism to do so.

        @see: U{XML Encoding Standard<http://www.w3schools.com/xml/xml_encoding.asp>}

        @param input_: the text to encode for XML

        @return: input encoded for use in XML
        """
        raise NotImplementedError()

    def encode_for_xml_attribute(self, input_):
        """
        Encode data for use in an XML attribute. The implementation should follow
        the U{XML Encoding Standard<http://www.w3schools.com/xml/xml_encoding.asp>}
        from the W3C.
        
        The use of a real XML parser is highly encouraged. However, in the
        hopefully rare case that you need to make sure that data is safe for
        inclusion in an XML document and cannot use a parse, this method provides
        a safe mechanism to do so.

        @see: U{XML Encoding Standard<http://www.w3schools.com/xml/xml_encoding.asp>}

        @param input_: the text to encode for use as an XML attribute

        @return: input encoded for use in an XML attribute
        """
        raise NotImplementedError()

    def encode_for_url(self, input_):
        """
        Encode for use in a URL. This method performs
        U{URL Encoding<http://en.wikipedia.org/wiki/Percent-encoding>}
        on the entire string.

        @see: U{URL encoding<http://en.wikipedia.org/wiki/Percent-encoding>}

        @param input_: the text to encode for use in a URL

        @return: input_ encoded for use in a URL

        @raises EncodingException: if encoding fails
        """
        raise NotImplementedError()

    def decode_from_url(self, input_):
        """
        Decode from URL. Implementations should first canonicalize and
        detect any double-encoding. If this check passes, then the data is decoded using URL
        decoding.

        @param input_: the text to decode from an encoded URL

        @return: the decoded URL value

        @raises EncodingException: if decoding fails
        """
        raise NotImplementedError()

    def encode_for_base64(self, input_):
        """
        Encode for Base64.

        @param input_: the text to encode for Base64

        @return: input encoded for Base64
        """
        raise NotImplementedError()

    def decode_from_base64(self, input_):
        """
        Decode data encoded with BASE-64 encoding.

        @param input_: the Base64 text to decode

        @return: input decoded from Base64

        @raises IOException:
        """
        raise NotImplementedError()


