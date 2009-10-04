#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@summary: The SecurityConfiguration interface stores all configuration 
    information that directs the behavior of the ESAPI implementation.
@copyright: Copyright (c) 2009 - The OWASP Foundation
@author: Craig Younkins (craig.younkins@owasp.org)
"""

class SecurityConfiguration:
    """
    The SecurityConfiguration interface stores all configuration information
    that directs the behavior of the ESAPI implementation.
    
    Protection of this configuration information is critical to the secure
    operation of the application using the ESAPI. You should use operating 
    system access controls to limit access to wherever the configuration 
    information is stored.
    
    Please note that adding another layer of encryption does not make the
    attackers job much more difficult. Somewhere there must be a master 
    "secret" that is stored unencrypted on the application platform. Creating 
    another layer of indirection doesn't provide any real additional security. 
    Its up to the reference implementation to decide whether this file should 
    be encrypted or not. The ESAPI reference implementation 
    (default_security_configuration.py) does not encrypt its properties file.
    
    @author: Craig Younkins (craig.younkins@owasp.org)
    """

    class Threshold:
        """
        Models a simple threshold as a count and an interval, along with a set 
        of actions to take if the threshold is exceeded. These thresholds are 
        used to define when the accumulation of a particular event has met a 
        set number within the specified time period. Once a threshold value 
        has been met, various actions can be taken at that point.
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
            Constructs a threshold that is composed of its name, its threshold 
            count, the time window for the threshold, and the actions to take 
            if the threshold is triggered.
            
            @param name: The name of this threshold.
            @param count: The count at which this threshold is triggered.
            @param interval: The time frame within which 'count' number of 
            actions has to be detected in order to trigger this threshold.
            @param actions: The list of actions to take if the threshold is met.
            """
            
            self.name = name
            self.count = count
            self.interval = interval
            self.actions = actions
            
    def __init__(self):
        pass

    # General   
    def get_application_name(self):
        """
        Gets the application name, used for logging
        
        @return: the name of the current application
        """
        raise NotImplementedError()
        
    def get_class_for_interface(self, interface):
        """
        Returns the class for a given interface name.
        
        @param interface: the module name in lowercase, eg. 'user' or 'encryptor'
        """
        raise NotImplementedError()
        
    def set_resource_directory(self, directory):
        """
        Sets the ESAPI resource directory.
        
        @param directory: The location of the resource directory.
        """
        raise NotImplementedError()
        
    def get_resource_file(self, filename):
        """
        Returns the full path to the filename in the resource directory. The
        file does not have to exist, as the caller may create it.
        
        @param filename: the filename to access inside the resources directory
        @return: The full path to the resource.
        """
        raise NotImplementedError()
        
    def get_character_encoding(self):
        """
        Gets the character encoding scheme supported by this application. This 
        is used to set the character encoding scheme on requests and responses 
        when set_character_encoding() is called on SafeRequests and 
        SafeResponses. This scheme is also used for encoding/decoding URLs and 
        any other place where the current encoding scheme needs to be known.
        
        Note: This does not get the configured response content type. That is 
        accessed by calling get_response_content_type().
        
        @return: the current character encoding scheme
        """
        raise NotImplementedError()

    # Authenticator
    def get_max_old_password_hashes(self):
        """
        Gets the maximum number of old password hashes that should be retained. 
        These hashes can be used to ensure that the user doesn't reuse the 
        specified number of previous passwords when they change their password.
        
        @return: the number of old hashed passwords to retain
        """
        raise NotImplementedError()
        
    def get_password_parameter_name(self):
        """
        Gets the name of the password parameter used during user 
        authentication.
        
        @return: the name of the password parameter
        """
        raise NotImplementedError()

    def get_username_parameter_name(self):
        """
        Gets the name of the username parameter used during user 
        authentication.
        
        @return: the name of the username parameter
        """
        raise NotImplementedError()
        
    def get_remember_token_duration(self):
        """
        Gets the length of the time to live window for remember me tokens as
        a timedelta object.
        
        @return: The time to live length for generated remember me tokens.
        """
        raise NotImplementedError()

    def get_session_idle_timeout_length(self):
        """
        Gets the idle timeout length for sessions as a timedelta object. This 
        is the amount of time that a session can live before it expires due to 
        lack of activity. Applications or frameworks could provide a 
        reauthenticate function that enables a session to continue after 
        reauthentication.
        
        @return: The session idle timeout length.
        """
        raise NotImplementedError()

    def get_session_absolute_timeout_length(self):
        """
        Gets the absolute timeout length for sessions as a timedelta object. 
        This is the amount of time that a session can live before it expires 
        regardless of the amount of user activity. Applications or frameworks 
        could provide a reauthenticate function that enables a session to 
        continue after reauthentication.
        
        @return: The session absolute timeout length.
        """
        raise NotImplementedError()
        
    def get_allowed_login_attempts(self):
        """
        Gets the number of login attempts allowed before the user's account is 
        locked. If this many failures are detected within the alloted time 
        period, the user's account will be locked.
        
        @return: the number of failed login attempts that cause an account to 
            be locked
        """
        raise NotImplementedError()
        
    # Encryption
    def get_encryption_keys_location(self):
        """
        Gets the directory that the encryption keys are under.
        
        @return: the directory of the encryption keys
        """
        raise NotImplementedError()
        
    def get_encryption_algorithm(self):
        """
        Gets the encryption algorithm used by ESAPI to protect data.
        
        @return: the current encryption algorithm
        """
        raise NotImplementedError()

    def get_encryption_key_length(self):
        """
        Gets the key length to use in cryptographic operations declared in the 
        ESAPI properties file.
        
        @return: the key length.
        """
        raise NotImplementedError()
        
    def get_digital_signature_algorithm(self):
        """
        Gets the digital signature algorithm used by ESAPI to generate and 
        verify signatures.
        
        @return: the current digital signature algorithm
        """
        raise NotImplementedError()

    def get_digital_signature_key_length(self):
        """
        Gets the digital signature key length used by ESAPI to generate and 
        verify signatures.
        
        @return: the current digital signature key length
        """
        raise NotImplementedError()
        
    # Executor
    def get_working_directory(self):
        """
        Returns the default working directory for executing native processes 
        with os.exec().
        """
        raise NotImplementedError()
    
    def get_allowed_executables(self):
        """
        Gets the allowed executables to run with the Executor.
        
        @return: a list of the current allowed executables
        """
        raise NotImplementedError()
        
    def get_max_running_time(self):
        """
        Returns the maximum length of time any process should be executed for 
        as a timedelta object.
        """
        raise NotImplementedError()        
        
    # Hashing
    def get_master_salt(self):
        """
        Gets the master salt that is used to salt stored password hashes and 
        any other location where a salt is needed.
        
        @return: the current master salt
        """
        raise NotImplementedError()

    def get_hash_algorithm(self):
        """
        Gets the hashing algorithm used by ESAPI to hash data.
        
        @return: the current hashing algorithm
        """
        raise NotImplementedError()

    def get_hash_iterations(self):
        """
        Gets the hash iterations used by ESAPI to hash data.
        
        @return: the current hashing algorithm
        """
        raise NotImplementedError()
        
    # HttpUtilities
    def get_force_http_only_cookies(self):
        """
        Forces new cookie headers with HttpOnly on first and second responses
        in public HttpSession esapi.filters.SafeRequest.getSession() and
        esapi.filters.getSession(boolean create)
        """
        raise NotImplementedError()
        
    def get_force_secure_cookies(self):
        """
        Forces new cookies to have Secure flag set.
        """
        raise NotImplementedError()
        
    def get_upload_directory(self):
        """
        Retrieves the default upload directory declared in the ESAPI 
        properties file.
        
        @return: the default upload directory declared in the ESAPI 
                properties file
        """
        raise NotImplementedError()
        
    def get_allowed_file_upload_size(self):
        """
        Gets the maximum allowed file upload size.
        
        @return: the current allowed file upload size
        """
        raise NotImplementedError()
        
    def get_response_content_type(self):
        """
        Gets the content type for responses used when set_safe_content_type() 
        is called.
        
        Note: This does not get the configured character encoding scheme. That 
        is accessed by calling get_character_encoding().
        
        @return: The current content-type set for responses.
        """
        raise NotImplementedError()
        
    def get_allowed_file_extensions(self):
        """
        Gets the allowed file extensions for files that are uploaded to this 
        application.
        
        @return: a list of the current allowed file extensions
        """
        raise NotImplementedError()
        
    # Intrusion Detector
    def get_quota(self, event_name):
        """
        Gets the intrusion detection quota for the specified event.
        
        @param event_name: the name of the event whose quota is desired
        
        @return: the Quota that has been configured for the specified type of 
                event
        """
        raise NotImplementedError()
        
    # Logging
    def get_log_encoding_required(self):
        """
        Returns whether HTML entity encoding should be applied to log entries.
        
        @return: True if log entries are to be HTML Entity encoded. False 
        otherwise.
        """
        raise NotImplementedError()

    def get_log_filename(self):
        """
        Get the name of the log file specified in the ESAPI configuration 
        properties file. Return a default value if it is not specified.
        
        @return: the log file name defined in the properties file.
        """
        raise NotImplementedError()

    def get_max_log_filesize(self):
        """
        Get the maximum size of a single log file from the ESAPI configuration 
        properties file. Return a default value if it is not specified. Once 
        the log hits this file size, it will roll over into a new log.
        
        @return: the maximum size of a single log file (in bytes).
        """
        raise NotImplementedError()
        
    # Validation
    def get_validation_pattern(self, type_name):
        """
        Returns the validation pattern for a particular type.
        """
        raise NotImplementedError()
