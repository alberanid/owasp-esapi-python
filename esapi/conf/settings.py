# Properties file for OWASP Enterprise Security API (ESAPI)
# You can find more information about ESAPI
# http://www.owasp.org/index.php/ESAPI
#
# WARNING: THIS FILE SHOULD ONLY CONTAIN SAFE DEFAULTS!!!!!
# TO CUSTOMIZE THIS FILE FOR YOUR INSTALLATION, SEE 'settings_local.template'
# SETTINGS DEFINED IN 'settings_local.py' WILL OVERRIDE THESE DEFAULTS!
#
# WARNING: Operating system protection should be used to lock down the conf
# resources directory and all the files inside.  Note that if you are using file-based
# implementations that some files may need to be read-write as they get
# updated dynamically.
#
# Before using, be sure to update the MasterKey and MasterSalt as described below.
#
#===========================================================================
# ESAPI Configuration
#
# ESAPI is designed to be easily extensible. You can use the reference implementation
# or implement your own providers to take advantage of your enterprise's security
# infrastructure. The functions in ESAPI are referenced using the ESAPI locator, like:
#
#      ESAPI.encryptor().encrypt( "Secret message" );
#
# Below you can specify the classname for the provider that you wish to use in your
# application. The only requirement is that it implement the appropriate ESAPI interface.
# This allows you to switch security implementations in the future without rewriting the
# entire application.
#
# DefaultAccessController requires ESAPI-AccessControlPolicy.xml in .esapi directory
ESAPI_access_control = 'esapi.reference.accesscontrol.DefaultAccessController'
# FileBasedAuthenticator requires users.txt file in .esapi directory
ESAPI_authenticator = 'esapi.reference.shelve_authenticator.ShelveAuthenticator'
ESAPI_encoder = 'esapi.reference.default_encoder.DefaultEncoder'
ESAPI_encryptor = 'esapi.reference.default_encryptor.DefaultEncryptor'
ESAPI_executor = 'esapi.reference.DefaultExecutor'
ESAPI_http_utilities = 'esapi.reference.default_http_utilities.DefaultHTTPUtilities'
ESAPI_intrusion_detector = 'esapi.reference.default_intrusion_detector.DefaultIntrusionDetector'
ESAPI_log_factory = 'esapi.reference.python_log_factory.PythonLogFactory'
ESAPI_randomizer = 'esapi.reference.default_randomizer.DefaultRandomizer'
ESAPI_validator = 'esapi.reference.default_validator.DefaultValidator'
ESAPI_user = 'esapi.reference.default_user.DefaultUser'

#===========================================================================
# ESAPI Authenticator
#
Authenticator_AllowedLoginAttempts = 5
Authenticator_MaxOldPasswordHashes = 12
Authenticator_UsernameParameterName = 'username'
Authenticator_PasswordParameterName = 'password'
# RememberTokenDuration (in days)
Authenticator_RememberTokenDuration = 14
# Session Timeouts (in minutes)
Authenticator_IdleTimeoutDuration = 20
Authenticator_AbsoluteTimeoutDuration = 20

#===========================================================================
# ESAPI Encryption
#
# The ESAPI Encryptor provides basic cryptographic functions with a simplified API.
# To get started, generate a new key using java -classpath esapi.jar esapi.reference.JavaEncryptor
# There is not currently any support for key rotation, so be careful when changing your key and salt as it
# will invalidate all signed, encrypted, and hashed data.
#
# WARNING: Not all combinations of algorithms and key lengths are supported.
# If you choose to use a key length greater than 128 (and you should), you must download the
# unlimited strength policy files and install in the lib directory of your JRE/JDK.
# See http://java.sun.com/javase/downloads/index.jsp for more information.
#
Encryptor_MasterKey = 'pJhlri8JbuFYDgkqtHmm9s0Ziug2PE7ovZDyEPm4j14='
Encryptor_MasterSalt = 'SbftnvmEWD5ZHHP+pX3fqugNysc='

# AES is the most widely used and strongest encryption algorithm
Encryptor_EncryptionKeyLength = 256
Encryptor_EncryptionAlgorithm = 'AES'

# Do not use DES except in a legacy situation
#Encryptor_EncryptionKeyLength=56
#Encryptor_EncryptionAlgorithm=DES

# TripleDES is considered strong enough for most purposes
#Encryptor_EncryptionKeyLength=168
#Encryptor_EncryptionAlgorithm=DESede

Encryptor_HashAlgorithm = 'SHA512'
Encryptor_HashIterations = 1024
Encryptor_DigitalSignatureMasterKey = 'KGlDcnlwdG8uUHVibGljS2V5LkRTQQpEU0FvYmoKcDAKKGRwMgpTJ3EnCnAzCkw5MDc3OTYyMjQyNjY4NDY3NTIwNTE3NjA1NDAzNTY5Nzg4MTMwMDEzMDExODc3MjlMCnNTJ3AnCnA0Ckw4OTg4NDY1Njc0MzExNTc5NTQzMzI3NjI2OTM4NTcwMjczOTc3MzM3NDcwNTk0ODc4MDA5ODY1NzU4NjY0OTk0NTYwNTU0NDgyODk1ODM1ODIzMjI1Mjc4NDI5NDA3MjM4NzIwODA2MDA5NDY0NzU4MTA2NDkwMzY1MDA5MzY2MjAwMzI1MTk0NzE3OTM2ODA3MzUzMDMzNjE0MjA5NjEzOTQ1NzEyMzQyNjYyNTE2NTgxNTIxMTI0MjcxNjA4NTA2MTU0NjU3NjA3MDU0NDAxODQ1MDgxNTI1Mjk1NTg5Nzk4Mjc4MjU5NDgwOTA5OTM2MDQyMDIxMjcwNzk5MDc4MDAzNTIxMTYwODY5MjY2ODQxNzA2OTQ4NzM0Mjc1NTI1MDg0MzMyODQ3NzQyNjY2Mjg5MUwKc1MneScKcDUKTDc5NDcwOTg5MTY5Njk0MDAxOTAxNDQxOTgzMzQ0MjUwNTQ1MzYyMjMzOTU1NTEyNTM3OTc4Njg5MzI2MDM5NjA0NjMzNTg3OTg4NDcxMzE4OTQ4NDIxNTUzNTc2OTEzNzUzNTgyMjcxMjc2NTYzNjI2OTI1MTY0MzA2MTI3NDQ5MjQ5OTAwMjExMDYzNDkyMjc2NTgwMDUyMzcwMTM0ODY1MjExMDA3MzcxMDIxMjYwMDM5NTU0OTEwNTQwMjU4NjUyMzI1MDMxMzI3MDY2OTE5MjQzOTYyNzg1MTczODc0OTA4MjM4ODcyMDI1MDkzNTg5MDA3MDg0NTM0ODc3MjIyNDA2MTcyNTE2MjYzODMwNzU5MzU3MTE3NTI5NDk1NDkyNDkyNzMxMTY0NDQzMTY5NDQ3TApzUydnJwpwNgpMMTYxMzUxODk2MjE3MjY1NzQ1NzAwNTQ0ODM4MjExMjQ3ODE5NTE2MzMyNDk1MzEwNjk3MzAxNTQ5MzE2NDAyNzE3MDE3MDEwODM0NDUzOTQzOTYwOTIzNjMwNzI2MTA1MjcwNDc2MzU0ODY5NDMzNzI3NDg3OTc2Mzg0NzY1NjAwMzI5MDQ5NzM3NjMzNTAzNzEzODU4ODEzMzE0OTQ2MzQ3MDkwOTQ3MDg4NDQ0NjE4ODg2OTcyMjcyNDI2ODQ1NjkwNzk0OTIxNDg5NjcwMDExMTg2ODgwMTkyNTQ2OTE4NTI0MDYwMzk3MTYxMDExMzIzNjEyNzgzNjUzMDk1MjI5MDM0NTUzODA4Mjk5MDIxOTc5MTkyMjYyMzIxNDgzNzYxMDU0MjI3MDc3NjAxOTgwNzRMCnNTJ3gnCnA3Ckw3OTE5MzAyOTA4NjI2MTI0MTk5NTk0ODE5NDg0MDc5MDI4MjcyODA0MDg5OTY1NjVMCnNiLg=='
Encryptor_DigitalSignatureAlgorithm = 'SHAwithDSA'
Encryptor_DigitalSignatureKeyLength = 1024
#Encryptor_RandomAlgorithm = 'SHA1PRNG'
Encryptor_CharacterEncoding = 'UTF-8'


#===========================================================================
# ESAPI HttpUtilties
#
# The HttpUtilities provide basic protections to HTTP requests and responses. Primarily these methods 
# protect against malicious data from attackers, such as unprintable characters, escaped characters,
# and other simple attacks. The HttpUtilities also provides utility methods for dealing with cookies,
# headers, and CSRF tokens.
#
HttpUtilities_UploadDir = r'UploadDir'
# Force HTTP only on all cookies in ESAPI SafeRequest
HttpUtilities_ForceHttpOnlySession = False
HttpUtilities_ForceSecureSession = False
HttpUtilities_ForceHttpOnlyCookies = True
HttpUtilities_ForceSecureCookies = True
# File upload configuration
HttpUtilities_AllowedUploadExtensions = '.zip,.pdf,.tar,.gz,.xls,.properties,.txt,.xml'.lower().split(',')
HttpUtilities_MaxUploadFileBytes = 5000000
# Using UTF-8 throughout your stack is highly recommended. That includes your database driver,
# container, and any other technologies you may be using. Failure to do this may expose you
# to Unicode transcoding injection attacks. Use of UTF-8 does not hinder internationalization.
HttpUtilities_ResponseContentType = 'text/html; charset=UTF-8'



#===========================================================================
# ESAPI Executor
Executor_WorkingDirectory = r'C:\Windows\Temp'
Executor_ApprovedExecutables = ()


#===========================================================================
# ESAPI Logging
# Set the application name if these logs are combined with other applications
Logger_ApplicationName = 'ESAPITest'
# If you use an HTML log viewer that does not properly HTML escape log data, you can set LogEncodingRequired to true
Logger_LogEncodingRequired = False
# LogFileName, the name of the logging file. Provide a full directory path (e.g., C:\\ESAPI\\ESAPI_logging_file) if you
# want to place it in a specific directory.
Logger_LogFileName = 'ESAPI_logging_file'
# MaxLogFileSize, the max size (in bytes) of a single log file before it cuts over to a new one (default is 10,000,000)
Logger_MaxLogFileSize = 10000000


#===========================================================================
# ESAPI Intrusion Detection
#
# Each event has a base to which .count, .interval, and .action are added
# The IntrusionException will fire if we receive "count" events within "interval" seconds
# The IntrusionDetector is configurable to take the following actions: log, logout, and disable
#  (multiple actions separated by commas are allowed e.g. event.test.actions=log,disable
#
# Custom Events
# Names must start with "event." as the base
# Use IntrusionDetector.addEvent( "test" ) in your code to trigger "event.test" here
#
IntrusionDetector_event_test_count = 2
IntrusionDetector_event_test_interval = 10
IntrusionDetector_event_test_actions = ('disable','log')

# Exception Events
# All EnterpriseSecurityExceptions are registered automatically
# Call IntrusionDetector.getInstance().addException(e) for Exceptions that do not extend EnterpriseSecurityException
# Use the fully qualified classname of the exception as the base

# any intrusion is an attack
IntrusionDetector_IntrusionException_count = 1
IntrusionDetector_IntrusionException_interval = 1
IntrusionDetector_IntrusionException_actions = ('log','disable','logout')

# for test purposes
IntrusionDetector_IntegrityException_count = 10
IntrusionDetector_IntegrityException_interval = 5
IntrusionDetector_IntegrityException_actions = ('log','disable','logout')

# rapid validation errors indicate scans or attacks in progress
# esapi.errors.ValidationException.count=10
# esapi.errors.ValidationException.interval=10
# esapi.errors.ValidationException.actions=log,logout

# sessions jumping between hosts indicates session hijacking
IntrusionDetector_AuthenticationHostException_count = 2
IntrusionDetector_AuthenticationHostException_interval = 10
IntrusionDetector_AuthenticationHostException_actions = ('log','logout')


#===========================================================================
# ESAPI Validation
#
# The ESAPI validator does many security checks on input, such as canonicalization
# and whitelist validation. Note that all of these validation rules are applied *after*
# canonicalization. Double-encoded characters (even with different encodings involved,
# are never allowed.
#
# To use:
#
# First set up a pattern below. You can choose any name you want, prefixed by the word
# "Validation." For example:
#   Validation.Email=^[A-Za-z0-9._%-]+@[A-Za-z0-9.-]+\\\\.[a-zA-Z]{2,4}$
# 
# Then you can validate in your code against the pattern like this:
#   Validator.getInstance().getValidDataFromBrowser( "Email", input );
#   Validator.getInstance().isValidDataFromBrowser( "Email", input );
#
# Converting Java regex to Python:
# Replace \\ with \
# Regex find\replace:  \\([^\\w\.\+\?\$\*\[\]])   ->  \1

#Validator_SafeString = r"""^[\p{L}\p{N}.]{0,1024}$"""
Validator_Email = r"""^[A-Za-z0-9._%-]+@[A-Za-z0-9.-]+\.[a-zA-Z]{2,4}$"""
Validator_IPAddress = r"""^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"""
# This regex modified slightly from Java version: ? just before $ has been removed
Validator_URL = r"""^(ht|f)tp(s?)://[0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*(:(0-9)*)*(/?)([a-zA-Z0-9-\.\?,:'/\\\+=&amp;%\$#_]*)$"""
Validator_CreditCard = r"""^(\d{4}[- ]?){3}\d{4}$"""
Validator_SSN = r"""^(?!000)([0-6]\d{2}|7([0-6]\d|7[012]))([ -]?)(?!00)\d\d\3(?!0000)\d{4}$"""

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

try:
    from settings_local import *
except ImportError:
    pass
