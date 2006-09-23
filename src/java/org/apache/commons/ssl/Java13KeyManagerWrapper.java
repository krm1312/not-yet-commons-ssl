/*
 * $Header$
 * $Revision$
 * $Date$
 *
 * ====================================================================
 *
 *  Copyright 2006 The Apache Software Foundation
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */

package org.apache.commons.ssl;

import com.sun.net.ssl.X509KeyManager;

import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class Java13KeyManagerWrapper implements X509KeyManager {

    private final X509KeyManager keyManager;
    private final KeyMaterial keyMaterial;
    private final SSL ssl;

    public Java13KeyManagerWrapper(X509KeyManager m, KeyMaterial km, SSL h) {
        this.keyManager = m;
        this.keyMaterial = km;
        this.ssl = h;
    }

    public String chooseClientAlias(String keyType, Principal[] issuers) {
        return keyManager.chooseClientAlias(keyType, issuers);
    }

    public String chooseServerAlias(String keyType, Principal[] issuers) {
        return keyManager.chooseServerAlias(keyType, issuers);
    }

    public X509Certificate[] getCertificateChain(String alias) {
        return keyManager.getCertificateChain(alias);
    }

    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return keyManager.getClientAliases(keyType, issuers);
    }

    public PrivateKey getPrivateKey(String alias) {
        return keyManager.getPrivateKey(alias);
    }

    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return keyManager.getServerAliases(keyType, issuers);
    }

}
