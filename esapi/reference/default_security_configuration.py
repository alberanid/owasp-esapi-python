# Todo
# Fix getResourceFile


import os
import os.path
import sys

REMEMBER_TOKEN_DURATION = "Authenticator.RememberTokenDuration"
IDLE_TIMEOUT_DURATION = "Authenticator.IdleTimeoutDuration"
ABSOLUTE_TIMEOUT_DURATION = "Authenticator.AbsoluteTimeoutDuration"
ALLOWED_LOGIN_ATTEMPTS = "Authenticator.AllowedLoginAttempts"
USERNAME_PARAMETER_NAME = "Authenticator.UsernameParameterName"
PASSWORD_PARAMETER_NAME = "Authenticator.PasswordParameterName"
MAX_OLD_PASSWORD_HASHES = "Authenticator.MaxOldPasswordHashes"

MASTER_KEY = "Encryptor.MasterKey"
MASTER_SALT = "Encryptor.MasterSalt"
KEY_LENGTH = "Encryptor.EncryptionKeyLength"
ENCRYPTION_ALGORITHM = "Encryptor.EncryptionAlgorithm"
HASH_ALGORITHM = "Encryptor.HashAlgorithm"
HASH_ITERATIONS = "Encryptor.HashIterations"
CHARACTER_ENCODING = "Encryptor.CharacterEncoding"
RANDOM_ALGORITHM = "Encryptor.RandomAlgorithm"
DIGITAL_SIGNATURE_ALGORITHM = "Encryptor.DigitalSignatureAlgorithm"
DIGITAL_SIGNATURE_KEY_LENGTH = "Encryptor.DigitalSignatureKeyLength"

WORKING_DIRECTORY = "Executor.WorkingDirectory"
APPROVED_EXECUTABLES = "Executor.ApprovedExecutables"

FORCE_HTTPONLY = "HttpUtilities.ForceHTTPOnly"
UPLOAD_DIRECTORY = "HttpUtilities.UploadDir"    
APPROVED_UPLOAD_EXTENSIONS = "HttpUtilities.ApprovedUploadExtensions"
MAX_UPLOAD_FILE_BYTES = "HttpUtilities.MaxUploadFileBytes"
RESPONSE_CONTENT_TYPE = "HttpUtilities.ResponseContentType"

APPLICATION_NAME = "Logger.ApplicationName"    
LOG_LEVEL = "Logger.LogLevel"
LOG_FILE_NAME = "Logger.LogFileName"
MAX_LOG_FILE_SIZE = "Logger.MaxLogFileSize"
LOG_ENCODING_REQUIRED = "Logger.LogEncodingRequired"
        
## The default max log file size is set to 10,000,000 bytes (10 Meg). If the current log file exceeds the current 
# max log file size, the logger will move the old log data into another log file. There currently is a max of 
# 1000 log files of the same name. If that is exceeded it will presumably start discarding the oldest logs.
DEFAULT_MAX_LOG_FILE_SIZE = 10000000
MAX_REDIRECT_LOCATION = 1000
MAX_FILE_NAME_LENGTH = 1000

# Implementation Keys
LOG_IMPLEMENTATION = "ESAPI.Logger"
AUTHENTICATION_IMPLEMENTATION = "ESAPI.Authenticator"
ENCODER_IMPLEMENTATION = "ESAPI.Encoder"
ACCESS_CONTROL_IMPLEMENTATION = "ESAPI.AccessControl"
ENCRYPTION_IMPLEMENTATION = "ESAPI.Encryptor"
INTRUSION_DETECTION_IMPLEMENTATION = "ESAPI.IntrusionDetector"
RANDOMIZER_IMPLEMENTATION = "ESAPI.Randomizer"
EXECUTOR_IMPLEMENTATION = "ESAPI.Executor"
VALIDATOR_IMPLEMENTATION = "ESAPI.Validator"
HTTP_UTILITIES_IMPLEMENTATION = "ESAPI.HTTPUtilities"

userDirectory = os.getenv('USERPROFILE') or os.getenv('HOME')

# Relative path to the resourceDirectory. Relative to the classpath. 
# Specifically, ClassLoader.getResource(resourceDirectory + filename) will
# be used to load the file.
resourceDirectory = ".esapi"

defaults = {
    REMEMBER_TOKEN_DURATION         : 14,
    IDLE_TIMEOUT_DURATION           : 20,
    ABSOLUTE_TIMEOUT_DURATION       : 20,
    ALLOWED_LOGIN_ATTEMPTS          : 5,
    USERNAME_PARAMETER_NAME         : "username",
    PASSWORD_PARAMETER_NAME         : "password",
    MAX_OLD_PASSWORD_HASHES         : 12,
    
    MASTER_KEY                      : None,
    MASTER_SALT                     : None,
    KEY_LENGTH                      : 256,
    ENCRYPTION_ALGORITHM            : "AES",
    HASH_ALGORITHM                  : "SHA-512",
    HASH_ITERATIONS                 : 1024,
    CHARACTER_ENCODING              : "UTF-8",
    RANDOM_ALGORITHM                : "SHA1PRNG",
    DIGITAL_SIGNATURE_ALGORITHM     : "SHAwithDSA",
    DIGITAL_SIGNATURE_KEY_LENGTH    : 1024,
    
    WORKING_DIRECTORY               : None,
    APPROVED_EXECUTABLES            : None,
    
    FORCE_HTTPONLY                  : True,
    UPLOAD_DIRECTORY                : "UploadDir",
    APPROVED_UPLOAD_EXTENSIONS      : ".zip,.pdf,.tar,.gz,.xls,.properties,.txt,.xml".split(','),
    MAX_UPLOAD_FILE_BYTES           : 5000000,
    RESPONSE_CONTENT_TYPE           : "text/html; charset=UTF-8",
    
    APPLICATION_NAME                : "DefaultName",
    LOG_LEVEL                       : "Warning",
    LOG_FILE_NAME                   : "ESAPI_logging_file",
    MAX_LOG_FILE_SIZE               : DEFAULT_MAX_LOG_FILE_SIZE,
    LOG_ENCODING_REQUIRED           : False,
    
    LOG_IMPLEMENTATION              : "esapi.reference.JavaLogFactory",
    AUTHENTICATION_IMPLEMENTATION   : "esapi.reference.FileBasedAuthenticator",
    ENCODER_IMPLEMENTATION          : "esapi.reference.DefaultEncoder",
    ACCESS_CONTROL_IMPLEMENTATION   : "esapi.reference.accesscontrol.DefaultAccessController",
    ENCRYPTION_IMPLEMENTATION       : "esapi.reference.JavaEncryptor",
    INTRUSION_DETECTION_IMPLEMENTATION : "esapi.reference.DefaultIntrusionDetector",
    RANDOMIZER_IMPLEMENTATION       : "esapi.reference.DefaultRandomizer",
    EXECUTOR_IMPLEMENTATION         : "esapi.reference.DefaultExecutor",
    VALIDATOR_IMPLEMENTATION        : "esapi.reference.DefaultHTTPUtilities",
    HTTP_UTILITIES_IMPLEMENTATION   : "esapi.reference.DefaultValidator",
    }

class DefaultSecurityConfiguration:
    def __init__(self):
        """Instantiates a new configuration"""
        #try:
        self.loadConfiguration()
#        except:
#            self.logSpecial("Failed to load security configuration")
            
    def loadConfiguration(self):
        """Load configuration"""
        
        self.config = ConfigParser.RawConfigParser(defaults)
        self.config.read(self.getResourceFile("ESAPI.properties"))
        self.logSpecial("Loaded ESAPI properties")
        
        self.logSpecial(" ======Master Configuration======")
        self.logSpecial("\tResourceDirectory: " + resourceDirectory)
        
        for option in self.config.options('ESAPI'):
            if "Master" not in option:
                self.logSpecial("  |   %(key)s = %(value)s" % {"key": option, "value": self.config.get('ESAPI', option)})
        
#    def getResourceStream(self, filename):
#        """
#        Utility method to get a resource and open it, returning the stream.
#        
#        """
#        file = self.getResourceFile(filename)
#        return open(file, 'r')
        
    def getResourceFile(self, filename):
        """
        """
        self.logSpecial("Seeking " + filename)
        
        path = "C:\\ESAPIPython\\ESAPI\\src\\test\\resources\\.esapi\\" + filename
        if os.path.isfile(path):
            sys.stdout.flush()
            return path
            
    def getApplicationName(self):
        return self.config.get("ESAPI", APPLICATION_NAME)

    def getLogImplementation(self):
        return self.config.get("ESAPI", LOG_IMPLEMENTATION)

    def getAuthenticationImplementation(self):
        return self.config.get("ESAPI", AUTHENTICATION_IMPLEMENTATION)

    def getEncoderImplementation(self):
        return self.config.get("ESAPI", ENCODER_IMPLEMENTATION)

    def getAccessControlImplementation(self):
        return self.config.get("ESAPI", ACCESS_CONTROL_IMPLEMENTATION)

    def getIntrusionDetectionImplementation(self):
        return self.config.get("ESAPI", INTRUSION_DETECTION_IMPLEMENTATION)

    def getRandomizerImplementation(self):
        return self.config.get("ESAPI", RANDOMIZER_IMPLEMENTATION)

    def getEncryptionImplementation(self):
        return self.config.get("ESAPI", ENCRYPTION_IMPLEMENTATION)

    def getValidationImplementation(self):
        return self.config.get("ESAPI", VALIDATOR_IMPLEMENTATION)
    
    def getExecutorImplementation(self):
        return self.config.get("ESAPI", EXECUTOR_IMPLEMENTATION)
    
    def getHTTPUtilitiesImplementation(self):
        return self.config.get("ESAPI", HTTP_UTILITIES_IMPLEMENTATION)
    
    def getMasterKey(self):
        return self.config.get("ESAPI", MASTER_KEY)
    
    def getUploadDirectory(self):
        return self.config.get("ESAPI", UPLOAD_DIRECTORY)

    def getEncryptionKeyLength(self):
        return self.config.get("ESAPI", KEY_LENGTH)

    def getMasterSalt(self):
        return self.config.get("ESAPI", MASTER_SALT)

    def getAllowedExecutables(self):
        return self.config.get("ESAPI", APPROVED_EXECUTABLES)

    def getAllowedFileExtensions(self):
        return self.config.get("ESAPI", APPROVED_UPLOAD_EXTENSIONS)

    def getAllowedFileUploadSize(self):
        return self.config.get("ESAPI", APPLICATION_NAME) ####

    def getPasswordParameterName(self):
        return self.config.get("ESAPI", PASSWORD_PARAMETER_NAME)

    def getUsernameParameterName(self):
        return self.config.get("ESAPI", USERNAME_PARAMETER_NAME)

    def getEncryptionAlgorithm(self):
        return self.config.get("ESAPI", ENCRYPTION_ALGORITHM)

    def getHashAlgorithm(self):
        return self.config.get("ESAPI", HASH_ALGORITHM)

    def getHashIterations(self):
        return self.config.get("ESAPI", HASH_ITERATIONS)

    def getCharacterEncoding(self):
        return self.config.get("ESAPI", CHARACTER_ENCODING)

    def getDigitalSignatureAlgorithm(self):
        return self.config.get("ESAPI", DIGITAL_SIGNATURE_ALGORITHM)

    def getDigitalSignatureKeyLength(self):
        return self.config.get("ESAPI", DIGITAL_SIGNATURE_KEY_LENGTH)

    def getRandomAlgorithm(self):
        return self.config.get("ESAPI", RANDOM_ALGORITHM)

    def getAllowedLoginAttempts(self):
        return self.config.get("ESAPI", ALLOWED_LOGIN_ATTEMPTS)

    def getMaxOldPasswordHashes(self):
        return self.config.get("ESAPI", MAX_OLD_PASSWORD_HASHES)

    def getQuota(self, eventName):
        return self.config.get("ESAPI", APPLICATION_NAME) ####

    def getForceHTTPOnly(self):
        return self.config.get("ESAPI", FORCE_HTTPONLY)

    def setResourceDirectory(self, dir):
        self.resourceDirectory = dir
        self.logSpecial( "Reset resource directory to: " + dir)
        
        # Reload configuration if necessary
        try:
            self.loadConfiguration()
        except e:
            self.logSpecial("Failed to load security configuration from " + dir, e)

    def getResponseContentType(self):
        return self.config.get("ESAPI", RESPONSE_CONTENT_TYPE)

    def getRememberTokenDuration(self):
        days = self.config.get("ESAPI", REMEMBER_TOKEN_DURATION)
        duration = 1000 * 60 * 60 * 24 * days
        return duration

    def getSessionIdleTimeoutLength(self):
        minutes = self.config.get("ESAPI", IDLE_TIMEOUT_DURATION)
        duration = 1000 * 60 * minutes
        return duration

    def getSessionAbsoluteTimeoutLength(self):
        minutes = self.config.get("ESAPI", ABSOLUTE_TIMEOUT_DURATION)
        duration = 1000 * 60 * minutes
        return duration

    def getLogEncodingRequired(self):
        return self.config.get("ESAPI", LOG_ENCODING_REQUIRED)

    def getLogFileName(self):
        return self.config.get("ESAPI", LOG_FILE_NAME)
    
    def getMaxLogFileSize(self):
        return self.config.get("ESAPI", MAX_LOG_FILE_SIZE)

    def getWorkingDirectory(self):
        return self.config.get("ESAPI", WORKING_DIRECTORY)
    
    def logSpecial(self, text):
        print text
        sys.stdout.flush()