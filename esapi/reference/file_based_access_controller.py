#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
@license: OWASP Enterprise Security API (ESAPI)
     
    This file is part of the Open Web Application Security Project (OWASP)
    Enterprise Security API (ESAPI) project. For details, please see
    U{http://www.owasp.org/index.php/ESAPI<http://www.owasp.org/index.php/ESAPI>}.

    The ESAPI is published by OWASP under the BSD license. You should read and 
    accept the LICENSE before you use, modify, and/or redistribute this software.
    
@copyright: Copyright (c) 2009 - The OWASP Foundation
@summary: Reference implementation of the AccessController interface.
@author: Craig Younkins (craig.younkins@owasp.org)
"""

from esapi.core import ESAPI
from esapi.translation import _
from esapi.access_controller import AccessController
from esapi.logger import Logger
from esapi.exceptions import AccessControlException, EncodingException, IntrusionException

class FileBasedAccessController(AccessController):
    """
    Reference implementation of the AccessController interface. This reference
    implementation uses a simple model for specifying a set of access control
    rules. Many organizations will want to create their own implementation of
    the methods provided in the AccessController interface.

    This reference implementation uses a simple scheme for specifying the
    rules. The first step is to create a namespace for the resources being
    accessed. For files and URL's, this is easy as they already have a 
    namespace. Be extremely careful about canonicalizing when relying on
    information from the user in an access control decision.
    
    For functions, data, and services, you will have to come up with your own
    namespace for the resources being accessed. You might simply define a flat
    namespace with a list of category names. For example, you might specify
    'FunctionA', 'FunctionB', and 'FunctionC'. Alternatively, you can create
    a richer namespace with a hierarchical structure, such as:
    
        - /functions
            - purchasing
            - shipping
            - inventory
        - /admin
            - createUser
            - deleteUser
            
    Once you've defined your namespace, you have to work out the rules that
    govern access to the different parts of the namespace. This 
    implementation allows you to attach a simple access control list (ACL) to
    any part of the namespace tree. The ACL lists a set of roles that are
    either allowed or denied access to a part of the tree. You specify these
    rules in a text file with a simple format.
    
    There is a single configuration file supporting each of the five methods
    in the AccessController interface. These files are located in the ESAPI
    resources directory. The use of a default deny rule is STRONGLY 
    recommended. The file format is as follows:
    
       path          | role        | allow/deny | comment
    ---------------------------------------------------------------
     * /banking/*    | user,admin  | allow      | authenticated users can access /banking
     * /admin        | admin       | allow      | only admin role can access /admin
     * /             | any         | deny       | default deny rule
    
    To find the matching rules, this implementation follows the general 
    approach used in Java EE when matching HTTP requests to servlets in 
    web.xml. The four mapping rules are used in the following order:
    
        - Exact match, e.g. /access/login
        - Longest path prefix match, beginning / and ending /*, e.g. /access/* or /*
        - Extension matching, beginning *., e.g. *.css
        - Default rule, specified by the single character pattern
    
    @author: Craig Younkins (craig.younkins@owasp.org)
    """
    
    URLACFILE = "URLAccessRules.txt"
    FUNCTIONACFILE = "FunctionAccessRules.txt"
    DATAACFILE = "DataAccessRules.txt"
    FILEACFILE = "FileAccessRules.txt"
    SERVICEACFILE = "ServiceAccessRules.txt"
    
    def __init__(self):
        self.url_map = {}
        self.function_map = {}
        self.data_map = {}
        self.file_map = {}
        self.service_map = {}
        
        self.deny = Rule()
        self.logger = ESAPI.logger("AccessController")
    
    def is_authorized_for_url(self, url):
        try:
            self.assert_authorized_for_url(url)
            return True
        except:
            return False
        
    def is_authorized_for_function(self, function_name):
        try:
            self.assert_authorized_for_function(function_name)
            return True
        except:
            return False
        
    def is_authorized_for_data(self, action, key):
        try:
            self.assert_authorized_for_data(action, key)
            return True
        except:
            return False
        
    def is_authorized_for_file(self, filepath):
        try:
            self.assert_authorized_for_file(filepath)
            return True
        except:
            return False
        
    def is_authorized_for_service(self, service_name):
        try:
            self.assert_authorized_for_service(service_name)
            return True
        except:
            return False
        
    def assert_authorized_for_url(self, url):
        if len(self.url_map) == 0:
            self.url_map = self.load_rules(self.URLACFILE)
        if not self.match_rule(self.url_map, url):
            raise AccessControlException(
                _("Not authorized for URL"), 
                _("Not authorized for URL: %(url)s") %
                 { 'url' : url } )
        
    def assert_authorized_for_function(self, function_name):        if len(self.function_map) == 0:
            self.function_map = self.load_rules(self.FUNCTIONACFILE)
        if not self.match_rule(self.function_map, function_name):
            raise AccessControlException(
                _("Not authorized for function"), 
                _("Not authorized for function: %(function)s") %
                 { 'function' : function_name } )
        
    def assert_authorized_for_data(self, action, key):
        if len(self.data_map) == 0:
            self.data_map = self.load_rules(self.DATAACFILE)
        if not self.match_rule(self.data_map, key, action):
            raise AccessControlException(
                _("Not authorized for data"), 
                _("Not authorized for data: %(data)s") %
                 { 'data' : key } )
        
    def assert_authorized_for_file(self, filepath):
        if len(self.file_map) == 0:
            self.file_map = self.load_rules(self.FILEACFILE)
        if not self.match_rule(self.file_map, filepath.replace("\\\\","/")):
            raise AccessControlException(
                _("Not authorized for file"), 
                _("Not authorized for file: %(file)s") %
                 { 'file' : filepath } )
    
    def assert_authorized_for_service(self, service_name):
        if len(self.service_map) == 0:
            self.service_map = self.load_rules(self.SERVICEACFILE)
        if not self.match_rule(self.service_map, service_name):
            raise AccessControlException(
                _("Not authorized for service"), 
                _("Not authorized for service: %(service)s") %
                 { 'service' : service_name } )
 
    def match_rule(self, dictionary, key, action=None):
        """
        Checks to see if the current user has access to the specified data,
        file, object, etc. If the user has access, as specified by the 
        dictionary parameter, this method returns True. If the user does not
        have access or an exception is thrown, false is returned.
        
        @param dictionary: the map/dictionary containing the access rules
        @param key: the path of the requested file, url, object, etc.
        
        @return: True, if the user has access. Otherwise, False.
        """
        # Get user's roles
        user = ESAPI.authenticator().current_user
        
        # Search for the first rule that matches the path and rules
        rule = self.search_for_rule(dictionary, user.roles, key)
        
        if action is None:
            return rule.allow
        else:
            return action.lower() in rule.actions
    
    def search_for_rule(self, dictionary, roles, key):
        """
        Search for the rule. Four mapping rules are used in order:
        
            - Exact match, e.g. /access/login
            - Longest path prefix match, beginning / and ending /*, e.g. /access/* or /*
            - Extension matching, beginning *., e.g. *.css
            - Default rule, specified by the single character pattern
            
        @param dictionary: the map containing the access rules
        @param roles: a list of roles the user has
        @param key: the file, url, object, etc. being checked for access
        @return: the rule stating whether to allow or deny access
        """
        canonical = None
        try:
            canonical = ESAPI.encoder().canonicalize(key)
        except EncodingException, extra:
            self.logger.warning( Logger.SECURITY_FAILURE, False,
                _("Failed to canonicalize input: %(key)s") %
                {'key' : key} )
                
        part = canonical
        if part is None:
            part = ""
            
        part.rstrip("/")
        
        if '..' in part:
            raise IntrusionException(
                _("Attempt to manipulate access control path"),
                _("Attempt to manipulate access control path: %(path)s") %
                {'path' : key} )
               
        # extract extension, if any
        extension = ''
        if part.rfind('.') != -1:
            extension = part.rsplit('.')[-1]
            
        # check for exact match - ignore any ending slash
        rule = dictionary.get(part)
        
        # check for ending with /*
        if rule is None:
            rule = dictionary.get(part + "/*")
        
        # check for matching extension rule *.ext
        if rule is None:
            rule = dictionary.get("*." + extension)
            
        # if rule found and user's rules match rule's rules, return the rule
        if rule is not None and self.overlap(rule.roles, roles):
            return rule
            
        # rule hasn't been found - if there are no more parts, return a deny
        slash = part.rfind('/')
        if slash == -1:
            return self.deny
                
        # if there are more parts, strip off the part and recurse
        part = part[:slash]
        
        # return the default deny
        if len(part) <= 1:
            return self.deny
            
        return self.search_for_rule(dictionary, roles, part)
        
    def overlap(self, rule_roles, user_roles):
        """
        This method returns True if there is overlap between the rule's rules
        and the user's roles.
        
        @param rule_roles: the rule roles
        @param user_roles: the user roles
        @return: True, if any roles exist in both lists. Otherwise, False.
        """
        if "any" in rule_roles:
            return True
            
        for role in user_roles:
            if role in rule_roles:
                return True
                
        return False
        
    def validate_roles(self, roles):
        """
        Checks that the roles passed in contain only letters, numbers, and
        underscores. Also checks that roles are no more than 10 characters long.
        If a role does not pass validation, it is not included in the list of
        roles returned by this method. A log warning is also generated for any
        invalid roles.
        
        @param roles: the list of roles to validate according to the criteria
            stated above.
        @return: a list of roles that are valid according to the criteria
            stated above.
        """
        ret = []
        for role in roles:
            canonical = ''
            try:
                stripped = role.strip()
                canonical = ESAPI.encoder().canonicalize(stripped)
            except EncodingException, extra:
                self.logger.warning( Logger.SECURITY_FAILURE,
                    _("Failed to canonicalize role: %(role)s") %
                    {'role' : stripped},
                    extra )
                    
            if not ESAPI.validator().is_valid_input(
                "Roles in FileBasedAccessController",
                canonical,
                "AccessControlRule", 200, False ):
                self.logger.warning( Logger.SECURITY_FAILURE,
                    _("Role is invalid, and was not added to the list of roles for this rule: %(role)s") %
                    {'role' : stripped} )
            else:
                ret.append(stripped)
       
        return ret
            
    def load_rules(self, rule_file):
        """
        Loads the access rules by storing them in a dictionary. This method
        reads the file specified by the rule_file parameter, ignoring any lines
        that begin with the '#' character as comments. Sections of the access
        rules file are split by the '|' character. The method loads all paths,
        replacing '\\\\' characters with '/' for uniformity, then loads the list
        of comma separated roles. The roles are validated to be sure they are
        within the length and character set limitations specified in the 
        validate_roles method. Then the permissions are stored for each item
        in the rules list.
        
        If the word 'allow' appears on the line, the specified roles are
        granted access to the data - otherwise, they will be denied access.
        
        Each path may only appear once in the access rules file. Any entry,
        after the first, containing the same path will be logged and ignored.
        
        @param rule_file: the name of the file that contains the access rules
        @return: a dictionary mapping path -> Rule object
        """
        ret = {}
        input_file = None
        try:
            filename = ESAPI.security_configuration().get_resource_file(rule_file)
            input_file = open(filename, 'r')
            line = ESAPI.validator().safe_read_line(input_file, 500)
            while line != '':
                line = line.strip()
                if len(line) > 0 and line[0] != '#':
                    rule = Rule()
                    parts = line.split('|')
                    
                    rule.path = parts[0].strip().replace("\\\\", "/")
                    
                    roles = parts[1].strip().lower().split(',')
                    roles = self.validate_roles(roles)
                    for role in roles:
                        rule.roles.append(role.strip())
                        
                    action = parts[2].strip().lower()
                    if action == 'allow' or action == 'deny':
                        rule.allow = action == 'allow'
                    else:
                        for act in action.split(','):
                            rule.actions.append(act.strip())
                    
                    if ret.has_key(rule.path):
                        self.logger.warning( Logger.SECURITY_FAILURE,
                            _("Problem in access control file. Duplicate rule ignored: %(rule)s") % 
                            {'rule' : rule} )
                    else:
                        ret[rule.path] = rule
                        
                line = ESAPI.validator().safe_read_line(input_file, 500)
            
        except Exception, extra:
            raise
            self.logger.warning( Logger.SECURITY_FAILURE, 
                _("Problem in access control file: %(file)s") % 
                {'file' : rule_file},
                extra )
        finally:
            try:
                input_file.close()
            except:
                self.logger.warning( Logger.SECURITY_FAILURE,
                    _("Failure closing access control file: %(file)s") %
                    {'file' : rule_file},
                    extra )
                    
        return ret
                    
class Rule:
    def __init__(self):
        self.path = ""
        self.roles = []
        self.allow = False
        self.actions = []
        
    def __str__(self):
        return ("URL:" + self.path + 
            " | " + str(self.roles) + 
            " | " + ("allow" if self.allow else "deny") +
            " | " + (str(self.actions) if self.actions else "-No Actions-"))

