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

import org.bouncycastle.jce.provider.JDKX509CertificateFactory;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 14-July-2006
 */
public class BouncyHelper {
    private static BouncyHelper instance = new BouncyHelper();
    private static JDKX509CertificateFactory factory;

    private BouncyHelper() {
        factory = new JDKX509CertificateFactory();
    }

    public static BouncyHelper getInstance() {
        return instance;
    }

    public X509Extension bouncyParse(X509Extension ext) {
        try {
            X509Certificate cert = (X509Certificate) ext;
            byte[] encoded = cert.getEncoded();
            InputStream in = new ByteArrayInputStream(encoded);
            Certificate c = factory.engineGenerateCertificate(in);
            if (c instanceof X509Certificate) {
                ext = (X509Certificate) c;
            }
        } catch (Exception e) {
        }
        return ext;
    }
}
