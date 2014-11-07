/*
 * Copyright 2014-2014 Hippo B.V. (http://www.onehippo.com)
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *         http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.onehippo.forge.security.support.shiro.realm;

import java.text.MessageFormat;
import java.util.HashSet;
import java.util.Set;

import javax.jcr.Credentials;
import javax.jcr.LoginException;
import javax.jcr.NodeIterator;
import javax.jcr.Repository;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.SimpleCredentials;
import javax.jcr.query.Query;
import javax.jcr.query.QueryResult;

import org.apache.shiro.authc.AccountException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.hippoecm.hst.site.HstServices;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Realm that allows authentication and authorization against Hippo Repository security data store.
 * <p/>
 * This realm supports caching by extending from {@link org.apache.shiro.realm.AuthorizingRealm}.
 */
public class HippoRepositoryRealm extends AuthorizingRealm {

    private static final Logger log = LoggerFactory.getLogger(HippoRepositoryRealm.class);

    private static final String DEFAULT_USER_QUERY = "//hippo:configuration/hippo:users/{0}";

    private static final String DEFAULT_GROUPS_OF_USER_QUERY = "//element(*, hipposys:group)[(@hipposys:members = ''{0}'' or @hipposys:members = ''*'') and @hipposys:securityprovider = ''internal'']";

    private static final String DEFAULT_ROLES_OF_USER_AND_GROUP_QUERY = "//hippo:configuration/hippo:domains/{0}/element(*, hipposys:authrole)[ @hipposys:users = ''{1}'' {2}]";

    private Repository systemRepository;

    private Credentials systemCreds;

    private String queryLanguage = Query.XPATH;

    private String userQuery = DEFAULT_USER_QUERY;

    private String groupsOfUserQuery = DEFAULT_GROUPS_OF_USER_QUERY;

    private String roleDomainName = "everywhere";

    private String rolesOfUserAndGroupQuery = DEFAULT_ROLES_OF_USER_AND_GROUP_QUERY;

    private String defaultRoleName;

    private String rolePrefix;

    private boolean permissionsLookupEnabled;

    public void setSystemRepository(Repository systemRepository) {
        this.systemRepository = systemRepository;
    }

    public Repository getSystemRepository() {
        if (systemRepository == null) {
            systemRepository = HstServices.getComponentManager().getComponent(Repository.class.getName());
        }

        return systemRepository;
    }

    public void setSystemCredentials(Credentials systemCreds) {
        this.systemCreds = systemCreds;
    }

    public Credentials getSystemCredentials() {
        if (systemCreds == null) {
            systemCreds = HstServices.getComponentManager().getComponent(
                    Credentials.class.getName() + ".hstconfigreader");
        }

        return systemCreds;
    }

    public void setQueryLanguage(String queryLanguage) {
        this.queryLanguage = queryLanguage;
    }

    public String getQueryLanguage() {
        return queryLanguage;
    }

    public String getUserQuery() {
        return userQuery;
    }

    public void setUserQuery(String userQuery) {
        this.userQuery = userQuery;
    }

    public void setGroupsOfUserQuery(String groupsOfUserQuery) {
        this.groupsOfUserQuery = groupsOfUserQuery;
    }

    public String getGroupsOfUserQuery() {
        return groupsOfUserQuery;
    }

    public void setRoleDomainName(String roleDomainName) {
        this.roleDomainName = roleDomainName;
    }

    public String getRoleDomainName() {
        return roleDomainName;
    }

    public void setRolesOfUserAndGroupQuery(String rolesOfUserAndGroupQuery) {
        this.rolesOfUserAndGroupQuery = rolesOfUserAndGroupQuery;
    }

    public String getRolesOfUserAndGroupQuery() {
        return rolesOfUserAndGroupQuery;
    }

    public void setDefaultRoleName(String defaultRoleName) {
        this.defaultRoleName = defaultRoleName;
    }

    public String getDefaultRoleName() {
        return defaultRoleName;
    }

    public String getRolePrefix() {
        return rolePrefix;
    }

    public void setRolePrefix(String rolePrefix) {
        this.rolePrefix = rolePrefix;
    }

    public boolean isPermissionsLookupEnabled() {
        return permissionsLookupEnabled;
    }

    public void setPermissionsLookupEnabled(boolean permissionsLookupEnabled) {
        this.permissionsLookupEnabled = permissionsLookupEnabled;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        Repository sysRepo = getSystemRepository();

        if (sysRepo == null) {
            throw new UnknownAccountException("Hippo Repository is not available now.");
        }

        UsernamePasswordToken upToken = (UsernamePasswordToken) token;
        String username = upToken.getUsername();

        // Null username is invalid
        if (username == null) {
            throw new AccountException("Null usernames are not allowed by this realm.");
        }

        char [] passwordChars = upToken.getPassword();

        SimpleAuthenticationInfo info = null;
        Session session = null;

        try {
            session = sysRepo.login(new SimpleCredentials(username, passwordChars));
            info = new SimpleAuthenticationInfo(username, passwordChars, getName());
        } catch (LoginException e) {
            throw new UnknownAccountException("No account found for user [" + username + "]", e);
        } catch (RepositoryException e) {
            throw new UnknownAccountException("No account found for user [" + username + "]", e);
        } finally {
            try {
                session.logout();
            } catch (Exception ignore) {
            }
        }

        return info;
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        //null usernames are invalid
        if (principals == null) {
            throw new AuthorizationException("PrincipalCollection method argument cannot be null.");
        }

        String username = (String) getAvailablePrincipal(principals);

        Set<String> roleNames = getRoleNames(username);
        Set<String> permissions = null;

        if (isPermissionsLookupEnabled()) {
            permissions = getPermissions(username, roleNames);
        }

        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo(roleNames);

        if (permissions != null) {
            info.setStringPermissions(permissions);
        }

        return info;
    }

    protected Set<String> getRoleNames(String username) throws AuthorizationException {
        Set<String> roleNames = new HashSet<String>();
        Session session = null;

        try {
            if (getSystemCredentials() != null) {
                session = getSystemRepository().login(getSystemCredentials());
            } else {
                session = getSystemRepository().login();
            }

            String statement = MessageFormat.format(getGroupsOfUserQuery(), username);

            if (log.isDebugEnabled()) {
                log.debug("Searching groups of user with query: " + statement);
            }

            Query q = session.getWorkspace().getQueryManager().createQuery(statement, getQueryLanguage());
            QueryResult result = q.execute();
            NodeIterator nodeIt = result.getNodes();

            StringBuilder groupsConstraintsBuilder = new StringBuilder(100);

            while (nodeIt.hasNext()) {
                String groupName = nodeIt.nextNode().getName();
                groupsConstraintsBuilder.append("or @hipposys:groups = '").append(groupName).append("' ");
            }

            statement = MessageFormat.format(getRolesOfUserAndGroupQuery(), getRoleDomainName(), username,
                    groupsConstraintsBuilder.toString());

            q = session.getWorkspace().getQueryManager().createQuery(statement, getQueryLanguage());
            result = q.execute();
            nodeIt = result.getNodes();

            boolean defaultRoleAdded = false;

            while (nodeIt.hasNext()) {
                String roleName = nodeIt.nextNode().getProperty("hipposys:role").getString();
                String prefixedRoleName = (rolePrefix != null ? rolePrefix + roleName : roleName);
                roleNames.add(prefixedRoleName);

                if (defaultRoleName != null && !defaultRoleAdded && roleName.equals(defaultRoleName)) {
                    defaultRoleAdded = true;
                }
            }

            if (defaultRoleName != null && !defaultRoleAdded) {
                String prefixedRoleName = (rolePrefix != null ? rolePrefix + defaultRoleName : defaultRoleName);
                roleNames.add(prefixedRoleName);
            }
        } catch (RepositoryException e) {
            final String message = "There was a repository exception while authorizing user [" + username + "]";

            if (log.isErrorEnabled()) {
                log.error(message, e);
            }

            // Rethrow any SQL errors as an authorization exception
            throw new AuthorizationException(message, e);
        } finally {
            if (session != null) {
                try {
                    session.logout();
                } catch (Exception ignore) {
                }
            }
        }

        return roleNames;
    }

    protected Set<String> getPermissions(String username, Set<String> roleNames) throws AuthorizationException {
        return null;
    }

}
