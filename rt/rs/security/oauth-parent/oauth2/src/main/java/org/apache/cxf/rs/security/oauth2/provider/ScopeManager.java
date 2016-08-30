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

import java.util.List;

import javax.ws.rs.core.MultivaluedMap;

import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.common.OAuthPermission;
import org.apache.cxf.rs.security.oauth2.common.UserSubject;

/**
 * This interface handles dynamically declared scopes.
 *
 * Blabla
 *
 * @author agonzalez
 */
public interface ScopeManager {
    /**
     * Returns client allowed permissions
     *
     * @param client OAuth Application
     * @param requestedScopes scopes requested by Application
     * @return permissions corresponding to the asked scope
     *
     * @throws OAuthServiceException if there's an error computing allowed permissions
     */
    List<OAuthPermission> allowedPermissions(Client client, List<String> requestedScopes);

    /**
     * Converts all requestedScopes to permission.
     *
     * @param client OAuth Application
     * @param requestedScopes scopes requested by Application
     * @return permissions corresponding to the asked scope
     *
     * @throws OAuthServiceException if conversion is not possible (i.e. a requestedScope is invalid)
     */
    List<OAuthPermission> convert(Client client, List<String> requestedScopes);

    boolean noConsentForRequestedScopes(MultivaluedMap<String, String> params,
                                      Client client,
                                      UserSubject userSubject,
                                      List<String> requestedScope,
                                      List<OAuthPermission> permissions);
}
