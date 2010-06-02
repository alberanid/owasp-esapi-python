#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: Default implementation of the Encryptor interface using Google's Keyczar.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

# Todo

import hashlib
import os
import time
from datetime import datetime, timedelta

try:
    from keyczar import keyczar
    from keyczar import keyczart as keyczartool
    from keyczar.errors import KeyczarError
except ImportError, err:
    module_name = err.args[-1].split()[-1]
    raise ImportError("%s\nSee: %s"
        % (err, 'http://www.keyczar.org/')) 

from esapi.core import ESAPI
from esapi.logger import Logger
from esapi.exceptions import EncryptionException, IntegrityException
from esapi.encryptor import Encryptor
from esapi.encoder import Encoder
from esapi.translation import _

class DefaultEncryptor(Encryptor):
    """
    Default implementation of the Encryptor interface using Google's Keyczar.
    """
    
    VALID_ENCRYPTION_ALGOS = ('AES')
    VALID_SIGNING_ALGOS = ('DSA')
    
    def __init__(self):
        Encryptor.__init__(self)
        self.logger = ESAPI.logger("DefaultEncryptor")
        
        # Hashing
        self.hash_algorithm = ESAPI.security_configuration().get_hash_algorithm()
        self.hash_iterations = ESAPI.security_configuration().get_hash_iterations()
        
        # Encryption
        self.encrypt_algorithm = ESAPI.security_configuration().get_encryption_algorithm()
        if self.encrypt_algorithm not in self.VALID_ENCRYPTION_ALGOS:
            raise EncryptionException(
                _("Encryption Failure - Unknown algorithm for encryption: %(algorithm)s") %
                {'algorithm' : self.encrypt_algorithm} )
        
        self.encryption_key_length = ESAPI.security_configuration().get_encryption_key_length()
        self.master_salt = ESAPI.security_configuration().get_master_salt()
        
        # Public key crypto
        self.signing_algorithm = ESAPI.security_configuration().get_digital_signature_algorithm()
        if self.signing_algorithm not in self.VALID_SIGNING_ALGOS:
            raise EncryptionException(
                _("Failure to encrypt"),
                _("Encryption Failure - Unknown algorithm for signing: %(algorithm)s") %
                {'algorithm' : self.signing_algorithm} )
        self.signing_key_length = ESAPI.security_configuration().get_digital_signature_key_length()
        
        # Key locations
        self.keys_location = os.path.realpath(ESAPI.security_configuration().get_encryption_keys_location()) + '/'
        self.keys_symmetric_location = self.keys_location + "symmetric"
        self.keys_asymmetric_private_location = self.keys_location + "asymmetric-private"
        self.keys_asymmetric_public_location = self.keys_location + "asymmetric-public"
             
    def hash(self, plaintext, salt, iterations=None):
        # Verify a MasterSalt has been set
        if not self.master_salt or len(self.master_salt) < 20:
            raise Exception(
                _("There is an error in the application configuration. The MasterSalt has not been set properly. Please see the instructions in the README for setting up a crypto keyring. Currently, Encryptor_MasterSalt=%(value)s") % 
                {'value' : self.master_salt})
    
        if iterations is None: 
            iterations = self.hash_iterations
    
        try:
            digest = hashlib.new(self.hash_algorithm)
            digest.update(self.master_salt)
            digest.update(salt)
            digest.update(plaintext)
            
            bytes = digest.digest()
            for i in range(self.hash_iterations):
                digest = hashlib.new(self.hash_algorithm)
                digest.update(bytes)
                bytes = digest.digest()
                
            encoded = ESAPI.encoder().encode_for_base64(bytes)
            return encoded
            
        except ValueError, e:
            raise EncryptionException(
                _("Problem hashing"),
                _("Internal Error - Can't find hash algorithm ") + self.hash_algorithm  
                )
        
    def encrypt(self, plaintext):
        try:
            crypter = keyczar.Crypter.Read(self.keys_symmetric_location)
            ciphertext = crypter.Encrypt(plaintext)
            return ciphertext
        except KeyczarError, err:
            raise EncryptionException(
                _("Problem encrypting"),
                _("Keyczar raised an error"),
                err )

    def decrypt(self, ciphertext):
        try:
            crypter = keyczar.Crypter.Read(self.keys_symmetric_location)
            plaintext = crypter.Decrypt(ciphertext)
            return plaintext
        except KeyczarError, err:
            raise EncryptionException(
                _("Problem decrypting"),
                _("Keyczar raised an error"),
                err )

    def sign(self, data):
        try:
            signer = keyczar.Signer.Read(self.keys_asymmetric_private_location)
            signature = signer.Sign(data)
            return signature
        except KeyczarError, err:
            raise EncryptionException(
                _("Problem signing"),
                _("Keyczar raised an error"),
                err )

    def verify_signature(self, signature, data):
        try:
            verifier = keyczar.Verifier.Read(self.keys_asymmetric_public_location)
            return verifier.Verify(data, signature)
        except KeyczarError, err:
            self.logger.warning( Logger.SECURITY_FAILURE,
                _("Keyczar raise an exception when verifying a signature"),
                err )
            return False

    def seal(self, data, expiration):
        try:
            if isinstance(expiration, datetime):
                expiration_seconds = time.mktime(expiration.timetuple())
            elif isinstance(expiration, timedelta):
                obj = datetime.now() + expiration
                expiration_seconds = time.mktime(obj.timetuple())
            else:
                expiration_seconds = expiration
        
            # Mix in some random data so even identical data and timestamp
            # produce different seals
            random = ESAPI.randomizer().get_random_string( 10,
                Encoder.CHAR_ALPHANUMERICS )
            plaintext = str(expiration_seconds) + ":" + random + ":" + data
            # add integrity check
            sig = self.sign(plaintext)
            ciphertext = self.encrypt(plaintext + ":" + sig)
            return ciphertext
        except EncryptionException, err:
            raise IntegrityException(
                err.user_message,
                err.log_message,
                err )

    def unseal(self, seal):
        try:
            plaintext = self.decrypt(seal)
            parts = plaintext.split(":")
            if len(parts) != 4:
                raise EncryptionException(
                    _("Invalid seal"),
                    _("Seal was not formatted properly") )
                    
            timestring = parts[0]
            expiration = datetime.fromtimestamp(float(timestring))
            if datetime.now() > expiration:
                raise EncryptionException(
                    _("Invalid seal"),
                    _("Seal has expired") )
            random, data, sig = parts[1:4]
            sig_data = timestring + ":" + random + ":" + data
            if not self.verify_signature(sig, sig_data):
                raise EncryptionException(
                    _("Invalid seal"),
                    _("Seal integrity check failed") )
                    
            return data
        except EncryptionException:
            raise
        except Exception, err:
            raise EncryptionException(
                _("Invalid seal"),
                _("Invalid seal"),
                err )
            
    def verify_seal(self, seal):
        try:
            self.unseal( seal )
            return True
        except:
            return False

    def gen_keys(self):
        """
        Create new keys.
        """
        print (_("Creating new keys in %(location)s") % 
            {'location' : self.keys_location} )
            
        # Create symmetric key
        os.makedirs(self.keys_symmetric_location)
        keyczartool.main(
            ['create', 
             "--location=%s" % self.keys_symmetric_location,
             "--purpose=crypt"] )
        keyczartool.main(
            ['addkey', 
             "--location=%s" % self.keys_symmetric_location,
             "--status=primary",
             "--size=%s" % self.encryption_key_length] )
             
        # Create asymmetric private keys for signing
        os.makedirs(self.keys_asymmetric_private_location)
        keyczartool.main(
            ['create', 
             "--location=%s" % self.keys_asymmetric_private_location,
             "--purpose=sign",
             "--asymmetric=%s" % self.encrypt_algorithm] )
        keyczartool.main(
            ['addkey', 
             "--location=%s" % self.keys_asymmetric_private_location,
             "--status=primary",
             "--size=%s" % self.signing_key_length] )
             
        # Extract public keys for signing
        os.makedirs(self.keys_asymmetric_public_location)
        keyczartool.main(
            ['create', 
             "--location=%s" % self.keys_asymmetric_public_location,
             "--purpose=sign",
             "--asymmetric=%s" % self.encrypt_algorithm] )
        keyczartool.main(
            ['pubkey', 
             "--location=%s" % self.keys_asymmetric_private_location,
             "--status=primary",
             "--destination=%s" % self.keys_asymmetric_public_location] )
             
        # Gen a new master salt
        from os import urandom
        salt = urandom(20)
        print "Please modify this line in esapi/conf/settings.py:"
        print "Encryptor_MasterSalt = '" + ESAPI.encoder().encode_for_base64(salt) + "'"
             
        print "Done!"
