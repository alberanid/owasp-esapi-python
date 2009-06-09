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

class ImportSettingsError(): pass

try:
    import esapi.conf.settings as settings
except ImportError:
    raise ImportSettingsError, "Unable to import settings file - Check settings.py"

class DefaultSecurityConfiguration:
    def __init__(self):
        """Instantiates a new configuration"""
        self.loadConfiguration()
            
    def loadConfiguration(self):
        """Load configuration"""
            
        self.logSpecial("Loaded ESAPI properties")
        
        self.logSpecial(" ======Master Configuration======")
        
        for option in dir(settings):
            if "Master" not in option and option[0] != "_":
                self.logSpecial("  |   %(key)s = %(value)s" % {"key": option, "value": str(settings.__dict__[option])})
           
    def getApplicationName(self):
        return settings.Logger_ApplicationName

    def getLogImplementation(self):
        return settings.ESAPI_Logger

    def getAuthenticationImplementation(self):
        return settings.ESAPI_Authenticator

    def getEncoderImplementation(self):
        return settings.ESAPI_Encoder

    def getAccessControlImplementation(self):
        return settings.ESAPI_AccessControl

    def getIntrusionDetectionImplementation(self):
        return settings.ESAPI_IntrusionDetector

    def getRandomizerImplementation(self):
        return settings.ESAPI_Randomizer

    def getEncryptionImplementation(self):
        return settings.ESAPI_Encryptor

    def getValidationImplementation(self):
        return settings.ESAPI_Validator
    
    def getExecutorImplementation(self):
        return settings.ESAPI_Executor
    
    def getHTTPUtilitiesImplementation(self):
        return settings.ESAPI_HTTPUtilities
    
    def getMasterKey(self):
        return settings.Encryptor_MasterKey
    
    def getUploadDirectory(self):
        return settings.HttpUtilities_UploadDir

    def getEncryptionKeyLength(self):
        return settings.Encryptor_EncryptionKeyLength

    def getMasterSalt(self):
        return settings.Encryptor_MasterSalt

    def getAllowedExecutables(self):
        return settings.HttpUtilities_AllowedUploadExtensions

    def getAllowedFileExtensions(self):
        return settings.HttpUtilities_AllowedUploadExtensions

    def getAllowedFileUploadSize(self):
        return settings.HttpUtilities_MaxUploadFileBytes

    def getPasswordParameterName(self):
        return settings.Authenticator_PasswordParameterName

    def getUsernameParameterName(self):
        return settings.Authenticator_UsernameParameterName

    def getEncryptionAlgorithm(self):
        return settings.Encryptor_EncryptionAlgorithm

    def getHashAlgorithm(self):
        return settings.Encryptor_HashAlgorithm

    def getHashIterations(self):
        return settings.Encryptor_HashIterations

    def getCharacterEncoding(self):
        return settings.Encryptor_CharacterEncoding

    def getDigitalSignatureAlgorithm(self):
        return settings.Encryptor_DigitalSignatureAlgorithm

    def getDigitalSignatureKeyLength(self):
        return settings.Encryptor_DigitalSignatureKeyLength

    def getRandomAlgorithm(self):
        return settings.Encryptor_RandomAlgorithm

    def getAllowedLoginAttempts(self):
        return settings.Authenticator_AllowedLoginAttempts

    def getMaxOldPasswordHashes(self):
        return settings.Authenticator_MaxOldPasswordHashes

    def getQuota(self, eventName):
        count = getattr(settings, "IntrusionDetector_" + eventName + "_count", 0)
        interval = getattr(settings, "IntrusionDetector_" + eventName + "_interval", 0)
        actions = interval = getattr(settings, "IntrusionDetector_" + eventName + "_actions", ())
        if count > 0 and interval > 0 and len(actions) > 0:
            return Threshold( eventName, count, interval, actions)

    def getForceHTTPOnly(self):
        return settings.HttpUtilities_ForceHTTPOnly

    def getResponseContentType(self):
        return settings.HttpUtilities_ResponseContentType

    def getRememberTokenDuration(self):
        days = settings.Authenticator_RememberTokenDuration
        duration = 1000 * 60 * 60 * 24 * days
        return duration

    def getSessionIdleTimeoutLength(self):
        minutes = settings.Authenticator_IdleTimeoutDuration
        duration = 1000 * 60 * minutes
        return duration

    def getSessionAbsoluteTimeoutLength(self):
        minutes = settings.Authenticator_AbsoluteTimeoutDuration
        duration = 1000 * 60 * minutes
        return duration

    def getLogEncodingRequired(self):
        return settings.Logger_LogEncodingRequired

    def getLogFileName(self):
        return settings.Logger_LogFileName
    
    def getMaxLogFileSize(self):
        return settings.Logger_MaxLogFileSize

    def getWorkingDirectory(self):
        return settings.Executor_WorkingDirectory
    
    def logSpecial(self, text):
        print text