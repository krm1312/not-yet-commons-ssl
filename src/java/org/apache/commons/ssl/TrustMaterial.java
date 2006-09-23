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

import java.io.*;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 27-Feb-2006
 */
public class TrustMaterial extends TrustChain {
    public final static TrustMaterial CACERTS;
    public final static TrustMaterial JSSE_CACERTS;
    public final static TrustMaterial TRUST_ALL = new TrustMaterial();
    public final static TrustMaterial TRUST_THIS_JVM = new TrustMaterial();	

    private final KeyStore jks;

    static {
        JavaImpl.load();
        String javaHome = System.getProperty("java.home");
        String pathToCacerts = javaHome + "/lib/security/cacerts";
        String pathToJSSECacerts = javaHome + "/lib/security/jssecacerts";
        TrustMaterial ca = null;
        TrustMaterial jsse = null;
        try {
            File f = new File(pathToCacerts);
            if (f.exists()) {
                ca = new TrustMaterial(pathToCacerts);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            File f = new File(pathToJSSECacerts);
            if (f.exists()) {
                jsse = new TrustMaterial(pathToJSSECacerts);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        CACERTS = ca;
        JSSE_CACERTS = jsse;
    }

    public TrustMaterial() {
        this.jks = null;
        addTrustMaterial(this);
    }

    public TrustMaterial(Collection x509Certs)
            throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        loadCerts(ks, x509Certs);
        this.jks = ks;
        addTrustMaterial(this);
    }

    public TrustMaterial(X509Certificate x509Cert)
            throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException {
        this(Collections.singleton(x509Cert));
    }

    public TrustMaterial(X509Certificate[] x509Certs)
            throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException {
        this(Arrays.asList(x509Certs));
    }

    public TrustMaterial(byte[] pemBase64)
            throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException {
        this(pemBase64, null);
    }

    public TrustMaterial(InputStream pemBase64)
            throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException {
        this(Util.streamToBytes(pemBase64));
    }

    public TrustMaterial(String pathToPemFile)
            throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException {
        this(new FileInputStream(pathToPemFile));
    }

    public TrustMaterial(File pemFile)
            throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException {
        this(new FileInputStream(pemFile));
    }

    public TrustMaterial(URL urlToPemFile)
            throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException {
        this(urlToPemFile.openStream());
    }

    public TrustMaterial(String pathToJksFile, char[] password)
            throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException {
        this(new File(pathToJksFile), password);
    }

    public TrustMaterial(File jksFile, char[] password)
            throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException {
        this(new FileInputStream(jksFile), password);
    }

    public TrustMaterial(URL urlToJKS, char[] password)
            throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException {
        this(urlToJKS.openStream(), password);
    }

    public TrustMaterial(InputStream jks, char[] password)
            throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException {
        this(Util.streamToBytes(jks), password);
    }


    public TrustMaterial(byte[] jks, char[] password)
            throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException {
        Collection certs = Collections.EMPTY_LIST;
        KeyStore ks = KeyStore.getInstance("jks");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream in = new ByteArrayInputStream(jks);

        // Instead of relying on file suffixes (e.g. *.jks), we figure out what
        // type of file we've got by analyzing the first 64 bytes.  If we find
        // the string "------BEGIN CERTIFICATE-----", then it's a PEM file.
        // Otherwise, it's a JKS file.
        String s = new String(jks, 0, 64);
        s = s.trim().toUpperCase(); // might as well be case-insensitive
        int x = s.indexOf("BEGIN CERTIFICATE");
        if (x >= 0) {
            // Since the word "BEGIN CERTIFICATE" was found, there's a good
            // chance our CertificateFactory can deal with this file.
            certs = cf.generateCertificates(in);
        }
        boolean isPEM = !certs.isEmpty();
        if (isPEM) {
            // It's definitely a PEM file!  It has "-----BEGIN CERTIFICATE----"
            // in it, and cf.generateCertificate() really worked!

            // small gotch'ya:  KeyStores aren't valid until load() has been
            // called on them.  So we just call load( null, null ).  Definitely
            // feels somehow wrong.  (ps.  usually password is null)
            ks.load(null, password);
            loadCerts(ks, certs);
        } else {
            try {
                // For fun, let's try pkcs12 format.
                in.reset();
                KeyStore pkcs12 = KeyStore.getInstance("PKCS12");
                pkcs12.load(in, password);
                ks = pkcs12;
            } catch (Exception e) {
                // It's probably a JKS file.  If not, this will throw a nice
                // exception.
                in.reset();
                ks.load(in, password);
            }
        }
        // overwrite password
        if (password != null && !(this instanceof KeyMaterial)) {
            for (int i = 0; i < password.length; i++) {
                password[i] = '*';
            }
        }
        this.jks = ks;
        addTrustMaterial(this);
    }

    public KeyStore getKeyStore() {
        return jks;
    }

    private static void loadCerts(KeyStore ks, Collection certs)
            throws KeyStoreException {
        Iterator it = certs.iterator();
        int count = 0;
        while (it.hasNext()) {
            X509Certificate cert = (X509Certificate) it.next();

            // I could be fancy and parse out the CN field from the
            // certificate's subject, but these names don't actually matter
            // at all - I think they just have to be unique.
            String alias = "commons-ssl-trustmaterial-" + count;
            ks.setCertificateEntry(alias, cert);
            count++;
        }
    }


}
