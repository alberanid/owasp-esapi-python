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

class SecurityConfiguration:
    """
    The SecurityConfiguration interface stores all configuration information
    that directs the behavior of the ESAPI implementation.
    <br><br>
    Protection of this configuration information is critical to the secure
    operation of the application using the ESAPI. You should use operating system
    access controls to limit access to wherever the configuration information is
    stored.
    <br><br>
    Please note that adding another layer of encryption does not make the
    attackers job much more difficult. Somewhere there must be a master "secret"
    that is stored unencrypted on the application platform. Creating another
    layer of indirection doesn't provide any real additional security. Its up to the
    reference implementation to decide whether this file should be encrypted or not.
    The ESAPI reference implementation (DefaultSecurityConfiguration.java) does not encrypt
    its properties file.
    
    @author Craig Younkins (craig.younkins@owasp.org)
    @since June 3, 2009
    """

    class Threshold:
        """
        Models a simple threshold as a count and an interval, along with a set of actions to take if
        the threshold is exceeded. These thresholds are used to define when the accumulation of a particular event
        has met a set number within the specified time period. Once a threshold value has been met, various
        actions can be taken at that point.
        """

        # The name of this threshold
        name = None
        
        # The count at which this threshold is triggered
        count = 0
        
        # The time frame which 'count' number of actions has to be detected
        # in order trigger this threshold
        interval = 0
        
        # The list of actions to take if the threshold is met.
        actions = None

        def __init__(self, name, count, interval, actions):
            """
            Constructs a threshold that is composed of its name, its threshold count, the time window for
            the threshold, and the actions to take if the threshold is triggered.
            
            @param name The name of this threshold.
            @param count The count at which this threshold is triggered.
            @param interval The time frame within which 'count' number of actions has to be detected in order to
            trigger this threshold.
            @param actions The list of actions to take if the threshold is met.
            """
            
            self.name = name
            self.count = count
            self.interval = interval
            self.actions = actions

    def getApplicationName(self):
        """
        Gets the application name, used for logging
        
        @return the name of the current application
        """
        raise NotImplementedError()

    def getLogImplementation(self):
        """
        Returns the fully qualified classname of the ESAPI Logging implementation.
        """
        raise NotImplementedError()

    def getAuthenticationImplementation(self):
        """
        Returns the fully qualified classname of the ESAPI Authentication implementation.
        """
        raise NotImplementedError()

    def getEncoderImplementation(self):
        """
        Returns the fully qualified classname of the ESAPI Encoder implementation.
        """
        raise NotImplementedError()

    def getAccessControlImplementation(self):
        """
        Returns the fully qualified classname of the ESAPI Access Control implementation.
        """
        raise NotImplementedError()

    def getIntrusionDetectionImplementation(self):
        """
        Returns the fully qualified classname of the ESAPI Intrusion Detection implementation.
        """
        raise NotImplementedError()

    def getRandomizerImplementation(self):
        """
        Returns the fully qualified classname of the ESAPI Randomizer implementation.
        """
        raise NotImplementedError()

    def getEncryptionImplementation(self):
        """
        Returns the fully qualified classname of the ESAPI Encryption implementation.
        """
        raise NotImplementedError()

    def getValidationImplementation(self):
        """
        Returns the fully qualified classname of the ESAPI Validation implementation.
        """
        raise NotImplementedError()

    def getExecutorImplementation(self):
        """
        Returns the fully qualified classname of the ESAPI OS Execution implementation.
        """
        raise NotImplementedError()

    def getHTTPUtilitiesImplementation(self):
        """
        Returns the fully qualified classname of the ESAPI HTTPUtilities implementation.
        """
        raise NotImplementedError()

    def getMasterKey(self):
        """
        Gets the master key. This password is used to encrypt/decrypt other files or types
        of data that need to be protected by your application.
        
        @return the current master key
        """
        raise NotImplementedError()

    def getUploadDirectory(self):
        """
        Retrieves the default upload directory declared in the ESAPI properties file.
        
        @return the default upload directory declared in the ESAPI properties file
        """
        raise NotImplementedError()

    def getEncryptionKeyLength(self):
        """
        Gets the key length to use in cryptographic operations declared in the ESAPI properties file.
        
        @return the key length.
        """
        raise NotImplementedError()

    def getMasterSalt(self):
        """
        Gets the master salt that is used to salt stored password hashes and any other location
        where a salt is needed.
        
        @return the current master salt
        """
        raise NotImplementedError()

    def getAllowedExecutables(self):
        """
        Gets the allowed executables to run with the Executor.
        
        @return a list of the current allowed file extensions
        """
        raise NotImplementedError()

    def getAllowedFileExtensions(self):
        """
        Gets the allowed file extensions for files that are uploaded to this application.
        
        @return a list of the current allowed file extensions
        """
        raise NotImplementedError()

    def getAllowedFileUploadSize(self):
        """
        Gets the maximum allowed file upload size.
        
        @return the current allowed file upload size
        """
        raise NotImplementedError()

    def getPasswordParameterName(self):
        """
        Gets the name of the password parameter used during user authentication.
        
        @return the name of the password parameter
        """
        raise NotImplementedError()

    def getUsernameParameterName(self):
        """
        Gets the name of the username parameter used during user authentication.
        
        @return the name of the username parameter
        """
        raise NotImplementedError()

    def getEncryptionAlgorithm(self):
        """
        Gets the encryption algorithm used by ESAPI to protect data.
        
        @return the current encryption algorithm
        """
        raise NotImplementedError()

    def getHashAlgorithm(self):
        """
        Gets the hashing algorithm used by ESAPI to hash data.
        
        @return the current hashing algorithm
        """
        raise NotImplementedError()

    def getHashIterations(self):
        """
        Gets the hash iterations used by ESAPI to hash data.
        
        @return the current hashing algorithm
        """
        raise NotImplementedError()

    def getCharacterEncoding(self):
        """
        Gets the character encoding scheme supported by this application. This is used to set the
        character encoding scheme on requests and responses when setCharacterEncoding() is called
        on SafeRequests and SafeResponses. This scheme is also used for encoding/decoding URLs
        and any other place where the current encoding scheme needs to be known.
        <br><br>
        Note: This does not get the configured response content type. That is accessed by calling
        getResponseContentType().
        
        @return the current character encoding scheme
        """
        raise NotImplementedError()

    def getDigitalSignatureAlgorithm(self):
        """
        Gets the digital signature algorithm used by ESAPI to generate and verify signatures.
        
        @return the current digital signature algorithm
        """
        raise NotImplementedError()

    def getDigitalSignatureKeyLength(self):
        """
        Gets the digital signature key length used by ESAPI to generate and verify signatures.
        
        @return the current digital signature key length
        """
        raise NotImplementedError()

    # def getRandomAlgorithm(self):
        # """
        # Gets the random number generation algorithm used to generate random numbers where needed.
        
        # @return the current random number generation algorithm
        # """
        # raise NotImplementedError()

    def getAllowedLoginAttempts(self):
        """
        Gets the number of login attempts allowed before the user's account is locked. If this
        many failures are detected within the alloted time period, the user's account will be locked.
        
        @return the number of failed login attempts that cause an account to be locked
        """
        raise NotImplementedError()

    def getMaxOldPasswordHashes(self):
        """
        Gets the maximum number of old password hashes that should be retained. These hashes can
        be used to ensure that the user doesn't reuse the specified number of previous passwords
        when they change their password.
        
        @return the number of old hashed passwords to retain
        """
        raise NotImplementedError()

    def getQuota(self, eventName):
        """
        Gets the intrusion detection quota for the specified event.
        
        @param eventName the name of the event whose quota is desired
        
        @return the Quota that has been configured for the specified type of event
        """
        raise NotImplementedError()

    def getResourceFile(self, filename):
        """
        Gets a file from the resource directory
        
        @param filename
        """
        raise NotImplementedError()

    def getForceHTTPOnly(self):
        """
        Forces new cookie headers with HttpOnly on first and second responses
        in public HttpSession esapi.filters.SafeRequest.getSession() and
        esapi.filters.getSession(boolean create)
        """
        raise NotImplementedError()

    def getResourceStream(self, filename):
        """
        Gets an InputStream to a file in the resource directory
        
        @param filename
        @return
        @raise IOException
        """
        raise NotImplementedError()

    def setResourceDirectory(self, dir):
        """
        Sets the ESAPI resource directory.
        
        @param dir The location of the resource directory.
        """
        raise NotImplementedError()

    def getResponseContentType(self):
        """
        Gets the content type for responses used when setSafeContentType() is called.
        <br><br>
        Note: This does not get the configured character encoding scheme. That is accessed by calling
        getCharacterEncoding().
        
        @return The current content-type set for responses.
        """
        raise NotImplementedError()

    def getRememberTokenDuration(self):
        """
        Gets the length of the time to live window for remember me tokens (in milliseconds).
        
        @return The time to live length for generated remember me tokens.
        """
        raise NotImplementedError()

    def getSessionIdleTimeoutLength(self):
        """
        Gets the idle timeout length for sessions (in milliseconds). This is the amount of time that a session
        can live before it expires due to lack of activity. Applications or frameworks could provide a reauthenticate
        function that enables a session to continue after reauthentication.
        
        @return The session idle timeout length.
        """
        raise NotImplementedError()

    def getSessionAbsoluteTimeoutLength(self):
        """
        Gets the absolute timeout length for sessions (in milliseconds). This is the amount of time that a session
        can live before it expires regardless of the amount of user activity. Applications or frameworks could
        provide a reauthenticate function that enables a session to continue after reauthentication.
        
        @return The session absolute timeout length.
        """
        raise NotImplementedError()

    def getLogEncodingRequired(self):
        """
        Returns whether HTML entity encoding should be applied to log entries.
        
        @return True if log entries are to be HTML Entity encoded. False otherwise.
        """
        raise NotImplementedError()

    def getLogFileName(self):
        """
        Get the name of the log file specified in the ESAPI configuration properties file. Return a default value
        if it is not specified.
        
        @return the log file name defined in the properties file.
        """
        raise NotImplementedError()

    def getMaxLogFileSize(self):
        """
        Get the maximum size of a single log file from the ESAPI configuration properties file. Return a default value
        if it is not specified. Once the log hits this file size, it will roll over into a new log.
        
        @return the maximum size of a single log file (in bytes).
        """
        raise NotImplementedError()

    def getWorkingDirectory(self):
        """
        Returns the default working directory for executing native processes with Runtime.exec().
        """
        raise NotImplementedError()
