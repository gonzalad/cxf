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

package org.apache.cxf.ws.security.wss4j.policyvalidators;

import java.util.Collection;

import javax.xml.namespace.QName;

import org.w3c.dom.Element;

import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.ws.policy.AssertionInfo;
import org.apache.wss4j.policy.SP11Constants;
import org.apache.wss4j.policy.SP12Constants;
import org.apache.wss4j.policy.model.Header;
import org.apache.wss4j.policy.model.RequiredParts;

/**
 * Validate a RequiredParts policy
 */
public class RequiredPartsPolicyValidator implements SecurityPolicyValidator {
    
    /**
     * Return true if this SecurityPolicyValidator implementation is capable of validating a 
     * policy defined by the AssertionInfo parameter
     */
    public boolean canValidatePolicy(AssertionInfo assertionInfo) {
        return assertionInfo.getAssertion() != null 
            && (SP12Constants.REQUIRED_PARTS.equals(assertionInfo.getAssertion().getName())
                || SP11Constants.REQUIRED_PARTS.equals(assertionInfo.getAssertion().getName()));
    }
    
    /**
     * Validate policies.
     */
    public void validatePolicies(PolicyValidatorParameters parameters, Collection<AssertionInfo> ais) {
        Element header = parameters.getSoapHeader();
        
        for (AssertionInfo ai : ais) {
            RequiredParts rp = (RequiredParts)ai.getAssertion();
            ai.setAsserted(true);
            for (Header h : rp.getHeaders()) {
                QName qName = new QName(h.getNamespace(), h.getName());
                if (header == null || DOMUtils.getFirstChildWithName((Element)header, qName) == null) {
                    ai.setNotAsserted("No header element of name " + qName + " found.");
                }
            }
        }
    }
    
}
