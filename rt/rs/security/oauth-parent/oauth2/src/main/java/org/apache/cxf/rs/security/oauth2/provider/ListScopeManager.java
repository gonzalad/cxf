/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.cxf.rs.security.oauth2.provider;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.MultivaluedMap;

import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.common.OAuthPermission;
import org.apache.cxf.rs.security.oauth2.common.UserSubject;

public class ListScopeManager implements ScopeManager {
    private Map<String, OAuthPermission> permissionMap = new HashMap<String, OAuthPermission>();
    private List<String> defaultScopes;
    private List<String> requiredScopes;
    private List<String> invisibleToClientScopes;
    private List<String> scopesRequiringNoConsent;

    public ListScopeManager() {
        this(new HashMap<String, String>());
    }

    public ListScopeManager(Map<String, String> supportedScopes) {
        setSupportedScopes(supportedScopes);
    }

    @Override
    public List<OAuthPermission> allowedPermissions(Client client, List<String> requestedScopes) {
        return convert(client, requestedScopes);
    }

    @Override
    public List<OAuthPermission> convert(Client client, List<String> requestedScopes) {
        if (requiredScopes() != null && !requestedScopes.containsAll(requiredScopes())) {
            throw new OAuthServiceException("Required scopes are missing");
        }
        if (requestedScopes.isEmpty()) {
            return Collections.emptyList();
        } else {
            List<OAuthPermission> list = new ArrayList<OAuthPermission>();
            for (String scope : requestedScopes) {
                list.add(convertScopeToPermission(client, scope));
            }
            if (!list.isEmpty()) {
                return list;
            }
        }
        throw new OAuthServiceException("Requested scopes can not be mapped");
    }

    protected OAuthPermission convertScopeToPermission(Client client, String scope) {
        OAuthPermission permission = permissionMap.get(scope);
        if (permission == null) {
            throw new OAuthServiceException("Unexpected scope: " + scope);
        }
        return permission;
    }

    @Override
    public boolean noConsentForRequestedScopes(MultivaluedMap<String, String> params,
                                             Client client,
                                             UserSubject userSubject,
                                             List<String> requestedScope,
                                             List<OAuthPermission> permissions) {
        return scopesRequiringNoConsent != null
                && requestedScope != null
                && requestedScope.size() == scopesRequiringNoConsent.size()
                && requestedScope.containsAll(scopesRequiringNoConsent);
    }

    public List<String> defaultScopes() {
        return defaultScopes;
    }

    public List<String> requiredScopes() {
        return requiredScopes;
    }

    public List<String> invisibleToClientScopes() {
        return invisibleToClientScopes;
    }

    public void setDefaultScopes(List<String> defaultScopes) {
        this.defaultScopes = defaultScopes;
        reBuildPermissions();
    }

    public void setRequiredScopes(List<String> requiredScopes) {
        this.requiredScopes = requiredScopes;
    }

    public void setInvisibleToClientScopes(List<String> invisibleToClientScopes) {
        this.invisibleToClientScopes = invisibleToClientScopes;
        reBuildPermissions();
    }

    public void setSupportedScopes(Map<String, String> scopes) {
        for (Map.Entry<String, String> entry : scopes.entrySet()) {
            OAuthPermission permission = new OAuthPermission(entry.getKey(), entry.getValue());
            permissionMap.put(entry.getKey(), permission);
        }
        reBuildPermissions();
    }

    public void setScopesRequiringNoConsent(List<String> scopesRequiringNoConsent) {
        this.scopesRequiringNoConsent = scopesRequiringNoConsent;
    }

    protected void reBuildPermissions() {
        for (OAuthPermission perm : permissionMap.values()) {
            if (defaultScopes != null && defaultScopes.contains(perm.getPermission())) {
                perm.setDefaultPermission(true);
            }
            if (invisibleToClientScopes != null && invisibleToClientScopes.contains(perm.getPermission())) {
                perm.setInvisibleToClient(true);
            }
        }
    }
}
