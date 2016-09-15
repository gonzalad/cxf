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
package org.apache.cxf.rs.security.oauth2.grants.code;

import org.apache.cxf.rs.security.oauth2.provider.JPAOAuthDataProvider;
import org.apache.cxf.rs.security.oauth2.provider.JPAOAuthDataProviderTest;
import org.junit.After;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * Runs the same tests as JPAOAuthDataProviderTest but within a Spring Managed Transaction.
 *
 * Spring spawns a transaction before each call to <code><oauthProvider</code>.
 *
 * @author agonzalez
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration("JPACMTCodeDataProvider.xml")
@ActiveProfiles("hibernate")
public class JPACMTOAuthDataProviderTest extends JPAOAuthDataProviderTest {

    @Autowired
    private JPACMTCodeDataProvider oauthProvider;

    @Override
    protected JPAOAuthDataProvider getProvider() {
        return this.oauthProvider;
    }

    @Before
    @Override
    public void setUp() {
        initializeProvider(oauthProvider);
    }

    @After
    @Override
    public void tearDown() {
    }
}
