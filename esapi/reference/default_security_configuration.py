#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: Reference implementation of the SecurityConfiguration interface.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

# Todo

import pickle
import re
import sys

from esapi.core import ESAPI
from esapi.security_configuration import SecurityConfiguration
from esapi.translation import _
from esapi.exceptions import ConfigurationException

try:
    import esapi.conf.settings as settings
except ImportError:
    raise ImportError, _("Unable to import settings file - Check settings.py")

class DefaultSecurityConfiguration(SecurityConfiguration):
    def __init__(self):
        """Instantiates a new configuration"""
        SecurityConfiguration.__init__(self)
        self.load_configuration()
            
    def load_configuration(self):
        """Load configuration"""
            
        self.log_special(_("Loaded ESAPI properties"))
        
        self.log_special(_(" ======Master Configuration======"))
        
        for option in dir(settings):
            if "Master" not in option and option[0] != "_":
                self.log_special("  |   %(key)s = %(value)s" % {"key": option, "value": str(settings.__dict__[option])})
           
    def get_application_name(self):
        return settings.Logger_ApplicationName
        
    def get_class_for_interface(self, interface):
        interface = interface.lower()
        prop = "ESAPI_%s" % (interface,)
        
        try:
            fqn = getattr(settings, prop)
        except AttributeError, extra:
            raise ConfigurationException( 
                _('There is an error in the application configuration'), 
                _("Class for this interface not specified in settings: %(interface)s") % 
                {'interface' : interface},
                extra )
        
        try:
            dot = fqn.rindex('.')
            modulename = fqn[:dot]
            classname = fqn[dot+1:]
        except ValueError, extra:
            raise ConfigurationException( 
                _('There is an error in the application configuration'), 
                _("Fully-qualified name is malformed: %(name)s") % 
                {'name' : fqn},
                extra )
        
        try:
            __import__(modulename)
            module = sys.modules[modulename]
            return getattr(module, classname)
        except (ImportError, AttributeError), extra:
            raise ConfigurationException(
                _('There is an error in the application configuration'),
                _('Error getting class %(class)s from module %(module)s') %
                {'class' : classname,
                 'module' : modulename,},
                 extra )

    def get_validation_pattern(self, key):
        value = getattr(settings, "Validator_" + key, None)
        if value is None: 
            self.log_special(_("Trying to get validation pattern Validator_%(key)s failed because it doesn't exist") %
            {'key' : key})
            return None
            
        try:
            return re.compile(value)
        except Exception, extra:
            self.log_special(_("SecurityConfiguration for Validator_%(key)s is not a valid regex in settings. Returning None.") % 
                {'key' : key})
            return None
    
    def get_master_key(self):
        return ESAPI.encoder().decode_from_base64(settings.Encryptor_MasterKey)
    
    def get_upload_directory(self):
        return settings.HttpUtilities_UploadDir

    def get_encryption_key_length(self):
        return settings.Encryptor_EncryptionKeyLength

    def get_master_salt(self):
        return ESAPI.encoder().decode_from_base64(settings.Encryptor_MasterSalt)

    def get_allowed_executables(self):
        return settings.HttpUtilities_AllowedUploadExtensions

    def get_allowed_file_extensions(self):
        return settings.HttpUtilities_AllowedUploadExtensions

    def get_allowed_file_upload_size(self):
        return settings.HttpUtilities_MaxUploadFileBytes

    def get_password_parameter_name(self):
        return settings.Authenticator_PasswordParameterName

    def get_username_parameter_name(self):
        return settings.Authenticator_UsernameParameterName

    def get_encryption_algorithm(self):
        return settings.Encryptor_EncryptionAlgorithm

    def get_hash_algorithm(self):
        return settings.Encryptor_HashAlgorithm

    def get_hash_iterations(self):
        return settings.Encryptor_HashIterations

    def get_character_encoding(self):
        return settings.Encryptor_CharacterEncoding

    def get_digital_signature_algorithm(self):
        return settings.Encryptor_DigitalSignatureAlgorithm

    def get_digital_signature_key_length(self):
        return settings.Encryptor_DigitalSignatureKeyLength

    def get_digital_signature_key(self):
        raw = settings.Encryptor_DigitalSignatureMasterKey
        decoded = ESAPI.encoder().decode_from_base64(raw)
        obj = pickle.loads(decoded)
        return obj

    def get_allowed_login_attempts(self):
        return settings.Authenticator_AllowedLoginAttempts

    def get_max_old_password_hashes(self):
        return settings.Authenticator_MaxOldPasswordHashes

    def get_quota(self, event_name):
        count = getattr(settings, "IntrusionDetector_" + event_name + "_count", 0)
        interval = getattr(settings, "IntrusionDetector_" + event_name + "_interval", 0)
        actions = interval = getattr(settings, "IntrusionDetector_" + event_name + "_actions", ())
        if count > 0 and interval > 0 and len(actions) > 0:
            return SecurityConfiguration.Threshold( event_name, count, interval, actions)

    def get_force_http_only_cookies(self):
        return settings.HttpUtilities_ForceHttpOnlyCookies
        
    def get_force_secure_cookies(self):
        return settings.HttpUtilities_ForceSecureCookies

    def get_response_content_type(self):
        return settings.HttpUtilities_ResponseContentType

    def get_remember_token_duration(self):
        days = settings.Authenticator_RememberTokenDuration
        duration = 1000 * 60 * 60 * 24 * days
        return duration

    def get_session_idle_timeout_length(self):
        minutes = settings.Authenticator_IdleTimeoutDuration
        duration = 1000 * 60 * minutes
        return duration

    def get_session_absolute_timeout_length(self):
        minutes = settings.Authenticator_AbsoluteTimeoutDuration
        duration = 1000 * 60 * minutes
        return duration

    def get_log_encoding_required(self):
        return settings.Logger_LogEncodingRequired

    def get_log_filename(self):
        return settings.Logger_LogFileName
    
    def get_max_log_filesize(self):
        return settings.Logger_MaxLogFileSize

    def get_working_directory(self):
        return settings.Executor_WorkingDirectory
    
    def log_special(self, text):
        print text