# Properties file for OWASP Enterprise Security API (ESAPI)
# You can find more information about ESAPI
# http://www.owasp.org/index.php/ESAPI
#
# WARNING: Operating system protection should be used to lock down the conf
# directory and all the files inside.  Note that if you are using file-based
# implementations that some files may need to be read-write as they get
# updated dynamically.
#
# Before using, be sure to update the MasterSalt as described below.
# This settings.py may be used, and contains only very safe defaults.
#
# This settings file is Python code, and must be syntactically correct.
# Use `python settings.py` from a shell to verify the syntax. If the syntax
# is correct, you should receive no output.
#
from datetime import timedelta

#===========================================================================
# ESAPI Provider Configuration
#
# ESAPI is designed to be easily extensible. You can use the reference 
# implementation or implement your own providers to take advantage of your 
# enterprise's security infrastructure. The functions in ESAPI are referenced 
# using the ESAPI locator, like:
#
#      from esapi.core import ESAPI
#      ESAPI.encryptor().encrypt( "Secret message" )
#
# Below you can specify the classname for the provider that you wish to use in 
# your application. The only requirement is that it implement the appropriate 
# ESAPI interface. This allows you to switch security implementations in the 
# future without rewriting the entire application.
#

ESAPI_access_controller = 'esapi.reference.file_based_access_controller.FileBasedAccessController'
ESAPI_access_reference_map = 'esapi.reference.random_access_reference_map.RandomAccessReferenceMap'
ESAPI_authenticator = 'esapi.reference.shelve_authenticator.ShelveAuthenticator'
ESAPI_encoder = 'esapi.reference.default_encoder.DefaultEncoder'
ESAPI_encryptor = 'esapi.reference.default_encryptor.DefaultEncryptor'
ESAPI_executor = 'esapi.reference.default_executor.DefaultExecutor'
ESAPI_http_utilities = 'esapi.reference.default_http_utilities.DefaultHTTPUtilities'
ESAPI_intrusion_detector = 'esapi.reference.default_intrusion_detector.DefaultIntrusionDetector'
ESAPI_log_factory = 'esapi.reference.python_log_factory.PythonLogFactory'
ESAPI_randomizer = 'esapi.reference.default_randomizer.DefaultRandomizer'
ESAPI_validator = 'esapi.reference.default_validator.DefaultValidator'
ESAPI_user = 'esapi.reference.default_user.DefaultUser'


#===========================================================================
# General Application configuration
#

# Set the application name if these logs are combined with other applications
General_ApplicationName = 'ESAPITest'


#===========================================================================
# ESAPI Authenticator
#

Authenticator_AllowedLoginAttempts = 5
Authenticator_MaxOldPasswordHashes = 12
Authenticator_UsernameParameterName = 'username'
Authenticator_PasswordParameterName = 'password'
Authenticator_RememberTokenDuration = timedelta(days=14)
Authenticator_IdleTimeoutDuration = timedelta(minutes=20)
Authenticator_AbsoluteTimeoutDuration = timedelta(minutes=20)


#===========================================================================
# ESAPI Encryption
#
# The ESAPI Encryptor provides basic cryptographic functions with a simplified API.
# To get started, generate new keys using the instructions in the README.
#
# WARNING: Not all combinations of algorithms and key lengths are supported.
# ESAPI leverages Google's Keyczar (http://www.keyczar.org/) to provide safe 
# and useful encryption. Keyczar has limitations on what algorithms are 
# available to encourage the use of the best ones.
#

# Directory in which keys are stored
Encryptor_KeysLocation = '/tmp/esapi/keyring'

# The master salt is appended to all hashes. 
# WARNING: THIS MUST BE CHANGED FROM THE DEFAULT BY FOLLOWING THE INSTRUCTIONS
# IN THE README TO GENERATE NEW ENCRYPTION KEYS
Encryptor_MasterSalt = None

# AES is the most widely used and strongest encryption algorithm
Encryptor_EncryptionAlgorithm = 'AES'
Encryptor_EncryptionKeyLength = 256

Encryptor_HashAlgorithm = 'SHA512'
Encryptor_HashIterations = 1024

Encryptor_DigitalSignatureAlgorithm = 'DSA'
Encryptor_DigitalSignatureKeyLength = 1024

Encryptor_CharacterEncoding = 'UTF-8'


#===========================================================================
# ESAPI HttpUtilties
#
# The HttpUtilities provide basic protections to HTTP requests and responses. 
# Primarily these methods protect against malicious data from attackers, such
# as unprintable characters, escaped characters, and other simple attacks. 
# The HttpUtilities also provides utility methods for dealing with cookies,
# headers, and CSRF tokens.
#

# Forces the "HTTPOnly" flag to be used on the session cookie
HttpUtilities_ForceHttpOnlySession = False
# Forces the "Secure" flag to be used on the session cookie
HttpUtilities_ForceSecureSession = False

# Forces the "HTTPOnly" flag to be used on all cookies
HttpUtilities_ForceHttpOnlyCookies = True
# Forces the "Secure" flag to be used on all cookies
HttpUtilities_ForceSecureCookies = True

# File upload configuration
HttpUtilities_UploadDir = r'UploadDir'
# A Python list of extensions allowed to be uploaded, including the period
HttpUtilities_AllowedUploadExtensions = []
HttpUtilities_MaxUploadFileBytes = 5000000
# Using UTF-8 throughout your stack is highly recommended. That includes your 
# database driver, container, and any other technologies you may be using. 
# Failure to do this may expose you to Unicode transcoding injection attacks. 
# Use of UTF-8 does not hinder internationalization.
HttpUtilities_ResponseContentType = 'text/html; charset=UTF-8'


#===========================================================================
# ESAPI Executor
#

# The directory in which files are executed
Executor_WorkingDirectory = r'/tmp'
# The executables your web application is allowed to execute
Executor_AllowedExecutables = ()
# If an executed process continues for this amount of time, it will be terminated
Executor_MaxRunningTime = timedelta(seconds=10)


#===========================================================================
# ESAPI Logging
#

# If you use an HTML log viewer that does not properly HTML escape log data, 
# you should set LogEncodingRequired to true
Logger_LogEncodingRequired = False
# The name of the logging file. Provide a full directory path 
# (e.g., C:\\ESAPI\\ESAPI_logging_file) if you want to place it in a specific 
# directory.
Logger_LogFileName = 'ESAPI_logging_file'
# The max size (in bytes) of a single log file before it cuts over to a new one 
# (default is 10,000,000)
Logger_MaxLogFileSize = 10000000


#===========================================================================
# ESAPI Intrusion Detection
#
# Each event has a base to which _count, _interval, and _action are added
# The IntrusionException will fire if we receive "count" events within 
# "interval" seconds
# The IntrusionDetector is configurable to take the following actions: 
#    log, logout, disable, and lock
# Multiple actions in a Python tuple are allowed
#    e.g. event_test_actions = ('log','disable')
#
# Custom Events
# Names must start with "IntrusionDetector_event_" as the base
# Use `ESAPI.intrusion_detector.add_event( "testEvent", "Log message" )` 
# in your code to trigger "event_test" here
#

IntrusionDetector_event_test_count = 2
IntrusionDetector_event_test_interval = 10
IntrusionDetector_event_test_actions = ('lock','log')

# Exception Events
# All EnterpriseSecurityExceptions are registered automatically
# Call ESAPI.intrusion_detector.add_exception(e) for Exceptions that do not 
# extend EnterpriseSecurityException
# Use the fully qualified classname of the exception as the base

# any intrusion is an attack
IntrusionDetector_IntrusionException_count = 1
IntrusionDetector_IntrusionException_interval = 1
IntrusionDetector_IntrusionException_actions = ('log','lock','logout')

# for test purposes
IntrusionDetector_IntegrityException_count = 10
IntrusionDetector_IntegrityException_interval = 5
IntrusionDetector_IntegrityException_actions = ('log','lock','logout')

# rapid validation errors indicate scans or attacks in progress
# IntrusionDetector_ValidationException_count = 10
# IntrusionDetector_ValidationException_interval = 10
# IntrusionDetector_ValidationException_actions = ('log', 'logout')

# sessions jumping between hosts indicates session hijacking
IntrusionDetector_AuthenticationHostException_count = 2
IntrusionDetector_AuthenticationHostException_interval = 10
IntrusionDetector_AuthenticationHostException_actions = ('log','logout')


#===========================================================================
# ESAPI Validation
#
# The ESAPI validator does many security checks on input, including 
# canonicalization and whitelist validation. Note that all of these validation
# rules are applied *after* canonicalization. Double-encoded characters 
# (even with different encodings involved, are never allowed.
#
# To use:
#
# First set up a pattern below. You can choose any name you want, prefixed by 
# the word "Validation_". It is a good idea to put regex strings in raw 
# triple-quoted strings.
# For example:
#   Validator_Email = r"""^[A-Za-z0-9._%-]+@[A-Za-z0-9.-]+\.[a-zA-Z]{2,4}$"""
# 
# Then you can validate in your code against the pattern like this:
#   ESAPI.validator().get_valid_input( "Context", input, "Email", 100, False )
#   ESAPI.validator().is_valid_input( "Context", input, "Email", 100, False )
#
Validator_Email = r"""^[A-Za-z0-9._%-]+@[A-Za-z0-9.-]+\.[a-zA-Z]{2,4}$"""
Validator_IPAddress = r"""^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"""
# This regex modified slightly from Java version: ? just before $ has been removed
Validator_URL = r"""^(ht|f)tp(s?)://[0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*(:(0-9)*)*(/?)([a-zA-Z0-9-\.\?,:'/\\\+=&amp;%\$#_]*)$"""
Validator_CreditCard = r"""^(\d{4}[- ]?){3}\d{4}$"""
Validator_SSN = r"""^(?!000)([0-6]\d{2}|7([0-6]\d|7[012]))([ -]?)(?!00)\d\d\3(?!0000)\d{4}$"""

# Validators for AccessControl
Validator_AccessControlRule = r"""^[a-zA-Z0-9_]{0,10}$"""

# Validators used by ESAPI
Validator_AccountName = r"""^[a-zA-Z0-9]{3,20}$"""
Validator_SystemCommand = r"""^[a-zA-Z-/]{0,64}$"""
Validator_RoleName = r"""^[a-z]{1,20}$"""
Validator_Redirect = r"""^/test.*$"""

# Global HTTP Validation Rules
# Values with Base64 encoded data (e.g. encrypted state) will need at least [a-zA-Z0-9/+=]
Validator_HTTPScheme = r"""^(http|https)$"""
Validator_HTTPServerName = r"""^[a-zA-Z0-9_.-]*$"""
Validator_HTTPParameterName = r"""^[a-zA-Z0-9_]{0,32}$"""
Validator_HTTPParameterValue = r"""^[a-zA-Z0-9.-/+=_ ]*$"""
Validator_HTTPCookieName = r"""^[a-zA-Z0-9-_]{0,32}$"""
Validator_HTTPCookieValue = r"""^[a-zA-Z0-9-/+=_ ]*$"""
Validator_HTTPHeaderName = r"""^[a-zA-Z0-9-_]{0,32}$"""
Validator_HTTPHeaderValue = r"""^[a-zA-Z0-9()-=\*\.\?;,+/:&_ ]*$"""
Validator_HTTPContextPath = r"""^[a-zA-Z0-9.-_]*$"""
Validator_HTTPPath = r"""^[a-zA-Z0-9.-_]*$"""
Validator_HTTPQueryString = r"""^[a-zA-Z0-9()-=\*\.\?;,+/:&_ ](1,50)$"""
Validator_HTTPURI = r"""^[a-zA-Z0-9()-=\*\.\?;,+/:&_ ]*$"""
Validator_HTTPURL = r"""^.*$"""
Validator_HTTPJSESSIONID = r"""^[A-Z0-9]{10,30}$"""

# Validation of file related input
Validator_Filename = r"""^[a-zA-Z0-9!@#$%^&{}\[\]()_+-=,.~'` ]{1,255}$"""
Validator_DirectoryName = r"""^[a-zA-Z0-9:\\!@#$%^&{}\[\]()_+-=,.~'` ]{1,255}$"""
