# Properties file for OWASP Enterprise Security API (ESAPI)
# You can find more information about ESAPI
# http://www.owasp.org/index.php/ESAPI
#
# WARNING: Operating system protection should be used to lock down the .esapi
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
'ESAPI.AccessControl' = 'esapi.reference.accesscontrol.DefaultAccessController"'
# FileBasedAuthenticator requires users.txt file in .esapi directory
'ESAPI.Authenticator' = 'esapi.reference.FileBasedAuthenticator'
'ESAPI.Encoder' = 'esapi.reference.DefaultEncoder'
'ESAPI.Encryptor' = 'esapi.reference.JavaEncryptor'
'ESAPI.Executor' = 'esapi.reference.DefaultExecutor'
'ESAPI.HTTPUtilities' = 'esapi.reference.DefaultHTTPUtilities'
'ESAPI.IntrusionDetector' = 'esapi.reference.DefaultIntrusionDetector'
# Log4JFactory Requires log4j.xml or log4j.properties in classpath - http://www.laliluna.de/log4j-tutorial.html
'ESAPI.Logger' = 'esapi.reference.Log4JLogFactory'
#ESAPI.Logger=esapi.reference.JavaLogFactory
'ESAPI.Randomizer' = 'esapi.reference.DefaultRandomizer'
'ESAPI.Validator' = 'esapi.reference.DefaultValidator'

#===========================================================================
# ESAPI Authenticator
#
'Authenticator.RememberTokenDuration' = 14
'Authenticator.AllowedLoginAttempts' = 3
'Authenticator.MaxOldPasswordHashes' = 13
'Authenticator.UsernameParameterName' = 'username'
'Authenticator.PasswordParameterName' = 'password'
# RememberTokenDuration (in days)
'Authenticator.RememberTokenDuration' = 14
# Session Timeouts (in minutes)
'Authenticator.IdleTimeoutDuration' = 20
'Authenticator.AbsoluteTimeoutDuration' = 120

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
'Encryptor.MasterKey' = 'pJhlri8JbuFYDgkqtHmm9s0Ziug2PE7ovZDyEPm4j14='
'Encryptor.MasterSalt' = 'SbftnvmEWD5ZHHP+pX3fqugNysc='

# AES is the most widely used and strongest encryption algorithm
'Encryptor.EncryptionKeyLength' = 256
'Encryptor.EncryptionAlgorithm' = 'AES'

# Do not use DES except in a legacy situation
#Encryptor.EncryptionKeyLength=56
#Encryptor.EncryptionAlgorithm=DES

# TripleDES is considered strong enough for most purposes
#Encryptor.EncryptionKeyLength=168
#Encryptor.EncryptionAlgorithm=DESede

'Encryptor.HashAlgorithm' = 'SHA-512'
'Encryptor.HashIterations' = 1024
'Encryptor.DigitalSignatureAlgorithm' = 'DSA'
'Encryptor.DigitalSignatureKeyLength' = 1024
'Encryptor.RandomAlgorithm' = 'SHA1PRNG'
'Encryptor.CharacterEncoding' = 'UTF-8'


#===========================================================================
# ESAPI HttpUtilties
#
# The HttpUtilities provide basic protections to HTTP requests and responses. Primarily these methods 
# protect against malicious data from attackers, such as unprintable characters, escaped characters,
# and other simple attacks. The HttpUtilities also provides utility methods for dealing with cookies,
# headers, and CSRF tokens.
#
# Default file upload location (remember to escape backslashes with \\)
'HttpUtilities.UploadDir' = r'C:\ESAPI\testUpload'
# Force HTTP only on all cookies in ESAPI SafeRequest
'HttpUtilities.ForceHTTPOnly' = False
# File upload configuration
'HttpUtilities.ApprovedUploadExtensions' = '.zip,.pdf,.doc,.docx,.ppt,.pptx,.tar,.gz,.tgz,.rar,.war,.jar,.ear,.xls,.rtf,.properties,.java,.class,.txt,.xml,.jsp,.jsf,.exe,.dll'
'HttpUtilities.MaxUploadFileBytes' = 500000000
# Using UTF-8 throughout your stack is highly recommended. That includes your database driver,
# container, and any other technologies you may be using. Failure to do this may expose you
# to Unicode transcoding injection attacks. Use of UTF-8 does not hinder internationalization.
'HttpUtilities.ResponseContentType' = 'text/html; charset=UTF-8'



#===========================================================================
# ESAPI Executor
'Executor.WorkingDirectory' = r'C:\Windows\Temp'
'Executor.ApprovedExecutables' = (r'C:\Windows\System32\cmd.exe', r'C:\Windows\System32\runas.exe')


#===========================================================================
# ESAPI Logging
# Set the application name if these logs are combined with other applications
'Logger.ApplicationName' = 'ESAPITest'
# If you use an HTML log viewer that does not properly HTML escape log data, you can set LogEncodingRequired to true
'Logger.LogEncodingRequired' = False
# LogFileName, the name of the logging file. Provide a full directory path (e.g., C:\\ESAPI\\ESAPI_logging_file) if you
# want to place it in a specific directory.
'Logger.LogFileName' = 'ESAPI_logging_file'
# MaxLogFileSize, the max size (in bytes) of a single log file before it cuts over to a new one (default is 10,000,000)
'Logger.MaxLogFileSize' = 10000000


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
'IntrusionDetector.event.test.count' = 2
'IntrusionDetector.event.test.interval' = 10
'IntrusionDetector.event.test.actions' = ('disable','log')

# Exception Events
# All EnterpriseSecurityExceptions are registered automatically
# Call IntrusionDetector.getInstance().addException(e) for Exceptions that do not extend EnterpriseSecurityException
# Use the fully qualified classname of the exception as the base

# any intrusion is an attack
'IntrusionDetector.esapi.errors.IntrusionException.count' = 1
'IntrusionDetector.esapi.errors.IntrusionException.interval' = 1
'IntrusionDetector.esapi.errors.IntrusionException.actions' = ('log','disable','logout')

# for test purposes
'IntrusionDetector.esapi.errors.IntegrityException.count' = 10
'IntrusionDetector.esapi.errors.IntegrityException.interval' = 5
'IntrusionDetector.esapi.errors.IntegrityException.actions' = ('log','disable','logout')

# rapid validation errors indicate scans or attacks in progress
# esapi.errors.ValidationException.count=10
# esapi.errors.ValidationException.interval=10
# esapi.errors.ValidationException.actions=log,logout

# sessions jumping between hosts indicates session hijacking
'IntrusionDetector.esapi.errors.AuthenticationHostException.count' = 2
'IntrusionDetector.esapi.errors.AuthenticationHostException.interval' = 10
'IntrusionDetector.esapi.errors.AuthenticationHostException.actions' = ('log','logout')


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
#   Validation.Email=^[A-Za-z0-9._%-]+@[A-Za-z0-9.-]+\\.[a-zA-Z]{2,4}$
# 
# Then you can validate in your code against the pattern like this:
#   Validator.getInstance().getValidDataFromBrowser( "Email", input );
#   Validator.getInstance().isValidDataFromBrowser( "Email", input );
#
'Validator.SafeString' = r'^[\p{L}\p{N}.]{0,1024}$'
'Validator.Email' = r'^[A-Za-z0-9._%-]+@[A-Za-z0-9.-]+\\.[a-zA-Z]{2,4}$'
'Validator.IPAddress' = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
'Validator.URL' = r'^(ht|f)tp(s?)\\:\\/\\/[0-9a-zA-Z]([-.\\w]*[0-9a-zA-Z])*(:(0-9)*)*(\\/?)([a-zA-Z0-9\\-\\.\\?\\,\\:\\'\\/\\\\\\+=&amp;%\\$#_]*)?$'
'Validator.CreditCard' = r'^(\\d{4}[- ]?){3}\\d{4}$'
'Validator.SSN' = r'^(?!000)([0-6]\\d{2}|7([0-6]\\d|7[012]))([ -]?)(?!00)\\d\\d\\3(?!0000)\\d{4}$'

# Validators used by ESAPI
'Validator.AccountName' = r'^[a-zA-Z0-9]{3,20}$'
'Validator.SystemCommand' = r'^[a-zA-Z\\-\\/]{0,64}$'
'Validator.RoleName' = r'^[a-z]{1,20}$'
'Validator.Redirect' = r'^\\/test.*$'

# Global HTTP Validation Rules
# Values with Base64 encoded data (e.g. encrypted state) will need at least [a-zA-Z0-9\/+=]
'Validator.HTTPScheme' = r'^(http|https)$'
'Validator.HTTPServerName' = r'^[a-zA-Z0-9_.\\-]*$'
'Validator.HTTPParameterName' = r'^[a-zA-Z0-9_]{0,32}$'
'Validator.HTTPParameterValue' = r'^[a-zA-Z0-9.\\-\\/+=_ ]*$'
'Validator.HTTPCookieName' = r'^[a-zA-Z0-9\\-_]{0,32}$'
'Validator.HTTPCookieValue' = r'^[a-zA-Z0-9\\-\\/+=_ ]*$'
'Validator.HTTPHeaderName' = r'^[a-zA-Z0-9\\-_]{0,32}$'
'Validator.HTTPHeaderValue' = r'^[a-zA-Z0-9()\\-=\\*\\.\\?;,+\\/:&_ ]*$'
'Validator.HTTPContextPath' = r'^[a-zA-Z0-9.\\-_]*$'
'Validator.HTTPPath' = r'^[a-zA-Z0-9.\\-_]*$'
'Validator.HTTPQueryString' = r'^[a-zA-Z0-9()\\-=\\*\\.\\?;,+\\/:&_ ](1,50)$'
'Validator.HTTPURI' = r'^[a-zA-Z0-9()\\-=\\*\\.\\?;,+\\/:&_ ]*$'
'Validator.HTTPURL' = r'^.*$'
'Validator.HTTPJSESSIONID' = r'^[A-Z0-9]{10,30}$'

# Validation of file related input
'Validator.FileName' = r'^[a-zA-Z0-9!@#$%^&{}\\[\\]()_+\\-=,.~'` ]{0,255}$'
'Validator.DirectoryName' = r'^[a-zA-Z0-9:\\\\!@#$%^&{}\\[\\]()_+\\-=,.~'` ]{0,255}$'

