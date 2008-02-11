/*
 * $HeadURL$
 * $Revision$
 * $Date$
 *
 * ====================================================================
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */

package org.apache.commons.ssl;

import org.apache.commons.ssl.asn1.ASN1EncodableVector;
import org.apache.commons.ssl.asn1.DERInteger;
import org.apache.commons.ssl.asn1.DERSequence;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

/**
 * Builds Java Key Store files out of pkcs12 files, or out of pkcs8 files +
 * certificate chains.  Also supports OpenSSL style private keys (encrypted or
 * unencrypted).
 *
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 4-Nov-2006
 */
public class KeyStoreBuilder {
    private final static String PKCS7_ENCRYPTED = "1.2.840.113549.1.7.6";

    public static KeyStore build(byte[] jksOrCerts, char[] password)
        throws IOException, CertificateException, KeyStoreException,
        NoSuchAlgorithmException, InvalidKeyException,
        NoSuchProviderException, ProbablyBadPasswordException,
        UnrecoverableKeyException {
        return build(jksOrCerts, null, password);
    }

    public static KeyStore build(byte[] jksOrCerts, byte[] privateKey,
                                 char[] password)
        throws IOException, CertificateException, KeyStoreException,
        NoSuchAlgorithmException, InvalidKeyException,
        NoSuchProviderException, ProbablyBadPasswordException,
        UnrecoverableKeyException {
        return build(jksOrCerts, privateKey, password, null);
    }


    public static KeyStore build(byte[] jksOrCerts, byte[] privateKey,
                                 char[] jksPassword, char[] aliasPassword)
        throws IOException, CertificateException, KeyStoreException,
        NoSuchAlgorithmException, InvalidKeyException,
        NoSuchProviderException, ProbablyBadPasswordException,
        UnrecoverableKeyException {

        if ( aliasPassword == null || aliasPassword.length <= 0 ) {
            aliasPassword = jksPassword;
        }

        BuildResult br1 = parse(jksOrCerts, jksPassword, aliasPassword);
        BuildResult br2 = null;
        KeyStore jks = null;
        if (br1.jks != null) {
            jks = br1.jks;
        } else if (privateKey != null && privateKey.length > 0) {
            br2 = parse(privateKey, jksPassword, aliasPassword);
            if (br2.jks != null) {
                jks = br2.jks;
            }
        }

        // If we happened to find a JKS file, let's just return that.
        // JKS files get priority (in case some weirdo specifies both a PKCS12
        // and a JKS file!).
        if (jks != null) {
            // Make sure the keystore we found is not corrupt.
            validate(jks, aliasPassword);
            return jks;
        }

        Key key = br1.key;
        X509Certificate[] chain = br1.chain;
        boolean atLeastOneNotSet = key == null || chain == null;
        if (atLeastOneNotSet && br2 != null) {
            if (br2.key != null) {
                // Notice that the key from build-result-2 gets priority over the
                // key from build-result-1 (if both had valid keys).
                key = br2.key;
            }
            if (chain == null) {
                chain = br2.chain;
            }
        }

        atLeastOneNotSet = key == null || chain == null;
        if (atLeastOneNotSet) {
            String missing = "";
            if (key == null) {
                missing = " [Private key missing (bad password?)]";
            }
            if (chain == null) {
                missing += " [Certificate chain missing]";
            }
            throw new KeyStoreException("Can't build keystore:" + missing);
        } else {

            X509Certificate theOne = buildChain(key, chain);
            String alias = "alias";
            // The theOne is not null, then our chain was probably altered.
            // Need to trim out the newly introduced null entries at the end of
            // our chain.
            if (theOne != null) {
                chain = Certificates.trimChain(chain);
                alias = Certificates.getCN(theOne);
                alias = alias.replace(' ', '_');
            }

            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, jksPassword);
            ks.setKeyEntry(alias, key, aliasPassword, chain);
            return ks;
        }
    }

    /**
     * Builds the chain up such that chain[ 0 ] contains the public key
     * corresponding to the supplied private key.
     *
     * @param key   private key
     * @param chain array of certificates to build chain from
     * @return theOne!
     * @throws KeyStoreException        no certificates correspond to private key
     * @throws CertificateException     java libraries complaining
     * @throws NoSuchAlgorithmException java libraries complaining
     * @throws InvalidKeyException      java libraries complaining
     * @throws NoSuchProviderException  java libraries complaining
     */
    public static X509Certificate buildChain(Key key, Certificate[] chain)
        throws CertificateException, KeyStoreException,
        NoSuchAlgorithmException, InvalidKeyException,
        NoSuchProviderException {
        X509Certificate theOne = null;
        if (key instanceof RSAPrivateCrtKey) {
            final RSAPrivateCrtKey rsa = (RSAPrivateCrtKey) key;
            BigInteger publicExponent = rsa.getPublicExponent();
            BigInteger modulus = rsa.getModulus();
            for (int i = 0; i < chain.length; i++) {
                X509Certificate c = (X509Certificate) chain[i];
                PublicKey pub = c.getPublicKey();
                if (pub instanceof RSAPublicKey) {
                    RSAPublicKey certKey = (RSAPublicKey) pub;
                    BigInteger pe = certKey.getPublicExponent();
                    BigInteger mod = certKey.getModulus();
                    if (publicExponent.equals(pe) && modulus.equals(mod)) {
                        theOne = c;
                    }
                }
            }
            if (theOne == null) {
                throw new KeyStoreException("Can't build keystore: [No certificates belong to the private-key]");
            }
            X509Certificate[] newChain;
            newChain = X509CertificateChainBuilder.buildPath(theOne, chain);
            Arrays.fill(chain, null);
            System.arraycopy(newChain, 0, chain, 0, newChain.length);
        }
        return theOne;
    }

    public static void validate(KeyStore jks, char[] keyPassword)
        throws CertificateException, KeyStoreException,
        NoSuchAlgorithmException, InvalidKeyException,
        NoSuchProviderException, UnrecoverableKeyException {
        Enumeration en = jks.aliases();
        String privateKeyAlias = null;
        while (en.hasMoreElements()) {
            String alias = (String) en.nextElement();
            boolean isKey = jks.isKeyEntry(alias);
            if (isKey) {
                if (privateKeyAlias != null) {
                    throw new KeyStoreException("Only 1 private key per keystore allowed for Commons-SSL");
                } else {
                    privateKeyAlias = alias;
                }
            }
        }
        if (privateKeyAlias == null) {
            throw new KeyStoreException("No private keys found in keystore!");
        }
        PrivateKey key = (PrivateKey) jks.getKey(privateKeyAlias, keyPassword);
        Certificate[] chain = jks.getCertificateChain(privateKeyAlias);
        X509Certificate[] x509Chain = Certificates.x509ifyChain(chain);
        X509Certificate theOne = buildChain(key, x509Chain);
        // The theOne is not null, then our chain was probably altered.
        // Need to trim out the newly introduced null entries at the end of
        // our chain.
        if (theOne != null) {
            x509Chain = Certificates.trimChain(x509Chain);
            jks.deleteEntry(privateKeyAlias);
            jks.setKeyEntry(privateKeyAlias, key, keyPassword, x509Chain);
        }
    }

    protected static class BuildResult {
        protected final Key key;
        protected final X509Certificate[] chain;
        protected final KeyStore jks;

        protected BuildResult(Key key, Certificate[] chain, KeyStore jks) {
            this.key = key;
            this.jks = jks;
            if (chain == null) {
                this.chain = null;
            } else if (chain instanceof X509Certificate[]) {
                this.chain = (X509Certificate[]) chain;
            } else {
                X509Certificate[] x509 = new X509Certificate[chain.length];
                for ( int i = 0; i < x509.length; i++ ) {
                    x509[i] = (X509Certificate) chain[i];
                }
                this.chain = x509;
            }
        }
    }


    public static BuildResult parse(byte[] stuff, char[] jksPass,
                                    char[] keyPass)
        throws IOException, CertificateException, KeyStoreException,
        ProbablyBadPasswordException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Key key = null;
        Certificate[] chain = null;
        try {
            PKCS8Key pkcs8Key = new PKCS8Key(stuff, jksPass);
            key = pkcs8Key.getPrivateKey();
        }
        catch (ProbablyBadPasswordException pbpe) {
            throw pbpe;
        }
        catch (GeneralSecurityException gse) {
            // no luck
        }

        List pemItems = PEMUtil.decode(stuff);
        Iterator it = pemItems.iterator();
        LinkedList certificates = new LinkedList();
        while (it.hasNext()) {
            PEMItem item = (PEMItem) it.next();
            byte[] derBytes = item.getDerBytes();
            String type = item.pemType.trim().toUpperCase();
            if (type.startsWith("CERT") ||
                type.startsWith("X509") ||
                type.startsWith("PKCS7")) {
                ByteArrayInputStream in = new ByteArrayInputStream(derBytes);
                X509Certificate c = (X509Certificate) cf.generateCertificate(in);
                certificates.add(c);
            }
            chain = toChain(certificates);
        }

        if (chain != null || key != null) {
            return new BuildResult(key, chain, null);
        }

        boolean isProbablyPKCS12 = false;
        boolean isASN = false;
        ASN1Structure asn1 = null;
        try {
            asn1 = ASN1Util.analyze(stuff);
            isASN = true;
            isProbablyPKCS12 = asn1.oids.contains(PKCS7_ENCRYPTED);
            if (!isProbablyPKCS12 && asn1.bigPayload != null) {
                asn1 = ASN1Util.analyze(asn1.bigPayload);
                isProbablyPKCS12 = asn1.oids.contains(PKCS7_ENCRYPTED);
            }
        }
        catch (Exception e) {
            // isProbablyPKCS12 and isASN are set properly by now.
        }

        ByteArrayInputStream stuffStream = new ByteArrayInputStream(stuff);
        BuildResult br = tryJKS(KeyStore.getDefaultType(), stuffStream, jksPass, keyPass);
        if (br == null) {
            br = tryJKS("jks", stuffStream, jksPass, keyPass);
            if (br == null) {
                br = tryJKS("jceks", stuffStream, jksPass, keyPass);
                if (br == null) {
                    br = tryJKS("BKS", stuffStream, jksPass, keyPass);
                }
            }
        }
        if (br != null) {
            return br;
        }
        if (isASN) {
            if (isProbablyPKCS12) {
                return tryJKS("pkcs12", stuffStream, jksPass, null);
            }
        } else {
            // Okay, it's ASN.1, but it's not PKCS12.  Only one possible
            // interesting things remains:  X.509.
            stuffStream.reset();

            try {
                certificates = new LinkedList();
                Collection certs = cf.generateCertificates(stuffStream);
                it = certs.iterator();
                while (it.hasNext()) {
                    X509Certificate x509 = (X509Certificate) it.next();
                    certificates.add(x509);
                }
                chain = toChain(certificates);
                if (chain != null && chain.length > 0) {
                    return new BuildResult(null, chain, null);
                }
            }
            catch (CertificateException ce) {
                // oh well
            }

            stuffStream.reset();
            // Okay, still no luck.  Maybe it's an ASN.1 DER stream
            // containing only a single certificate?  (I don't completely
            // trust CertificateFactory.generateCertificates).
            try {
                Certificate c = cf.generateCertificate(stuffStream);
                X509Certificate x509 = (X509Certificate) c;
                chain = toChain(Collections.singleton(x509));
                if (chain != null && chain.length > 0) {
                    return new BuildResult(null, chain, null);
                }
            }
            catch (CertificateException ce) {
                // oh well
            }
        }

        br = tryJKS("pkcs12", stuffStream, jksPass, null);
        if ( br != null ) {
            // no exception thrown, so must be PKCS12.
            System.out.println("Please report bug!");
            System.out.println("PKCS12 detection failed to realize this was PKCS12!");
            System.out.println(asn1);
            return br;
        }
        throw new KeyStoreException("failed to extract any certificates or private keys - maybe bad password?");
    }

    private static BuildResult tryJKS(String keystoreType,
                                      ByteArrayInputStream in,
                                      char[] jksPassword, char[] keyPassword)
        throws ProbablyBadPasswordException {
        in.reset();
        if (keyPassword == null || keyPassword.length <= 0) {
            keyPassword = jksPassword;
        }

        keystoreType = keystoreType.trim().toLowerCase();
        boolean isPKCS12 = "pkcs12".equalsIgnoreCase(keystoreType);
        try {
            Key key = null;
            Certificate[] chain = null;
            UnrecoverableKeyException uke = null;
            KeyStore jksKeyStore = KeyStore.getInstance(keystoreType);
            jksKeyStore.load(in, jksPassword);
            Enumeration en = jksKeyStore.aliases();
            while (en.hasMoreElements()) {
                String alias = (String) en.nextElement();
                if (jksKeyStore.isKeyEntry(alias)) {
                    try {
                        key = jksKeyStore.getKey(alias, keyPassword);
                        if (key != null && key instanceof PrivateKey) {
                            chain = jksKeyStore.getCertificateChain(alias);
                            break;
                        }
                    } catch (UnrecoverableKeyException e) {
                        uke = e;  // We might throw this one later. 
                    } catch (GeneralSecurityException gse) {
                        // Swallow... keep looping.
                    }
                }
                if (isPKCS12 && en.hasMoreElements()) {
                    System.out.println("what kind of weird pkcs12 file has more than one alias?");
                }
            }
            if (key == null && uke != null) {
                throw new ProbablyBadPasswordException("Probably bad JKS-Key password: " + uke);
            }
            if (isPKCS12) {
                // PKCS12 is supposed to be just a key and a chain, anyway.
                jksKeyStore = null;
            }
            return new BuildResult(key, chain, jksKeyStore);
        }
        catch ( ProbablyBadPasswordException pbpe ) {
            throw pbpe;
        }
        catch (GeneralSecurityException gse) {
            // swallow it, return null
            return null;
        }
        catch (IOException ioe) {
            String msg = ioe.getMessage();
            msg = msg != null ? msg.trim().toLowerCase() : "";
            if (isPKCS12) {
                int x = msg.indexOf("failed to decrypt");
                int y = msg.indexOf("verify mac");
                x = Math.max(x, y);
                if (x >= 0) {
                    throw new ProbablyBadPasswordException("Probably bad PKCS12 password: " + ioe);
                }
            } else {
                int x = msg.indexOf("password");
                if (x >= 0) {
                    throw new ProbablyBadPasswordException("Probably bad JKS password: " + ioe);
                }
            }
            // swallow it, return null.
            return null;
        }
    }

    private static X509Certificate[] toChain(Collection certs) {
        if (certs != null && !certs.isEmpty()) {
            X509Certificate[] x509Chain = new X509Certificate[certs.size()];
            certs.toArray(x509Chain);
            return x509Chain;
        } else {
            return null;
        }
    }


    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("KeyStoreBuilder:  creates '[alias].jks' (Java Key Store)");
            System.out.println("    -topk8 mode:  creates '[alias].pem' (x509 chain + unencrypted pkcs8)");
            System.out.println("[alias] will be set to the first CN value of the X509 certificate.");
            System.out.println("-------------------------------------------------------------------");
            System.out.println("Usage1: [password] [file:pkcs12]");
            System.out.println("Usage2: [password] [file:private-key] [file:certificate-chain]");
            System.out.println("Usage3: -topk8 [password] [file:jks]");
            System.out.println("-------------------------------------------------------------------");
            System.out.println("[private-key] can be openssl format, or pkcs8.");
            System.out.println("[password] decrypts [private-key], and also encrypts outputted JKS file.");
            System.out.println("All files can be PEM or DER.");
            System.exit(1);
        }
        char[] password = args[0].toCharArray();
        boolean toPKCS8 = false;
        if ("-topk8".equalsIgnoreCase(args[0])) {
            toPKCS8 = true;
            password = args[1].toCharArray();
            args[1] = args[2];
            args[2] = null;
        }

        FileInputStream fin1 = new FileInputStream(args[1]);
        byte[] bytes1 = Util.streamToBytes(fin1);
        byte[] bytes2 = null;
        if (args.length > 2 && args[2] != null) {
            FileInputStream fin2 = new FileInputStream(args[2]);
            bytes2 = Util.streamToBytes(fin2);
        }

        KeyStore ks = build(bytes1, bytes2, password);
        Enumeration en = ks.aliases();
        String alias = null;
        while (en.hasMoreElements()) {
            if (alias == null) {
                alias = (String) en.nextElement();
            } else {
                System.out.println("Generated keystore contains more than 1 alias!?!?");
            }
        }

        String suffix = toPKCS8 ? ".pem" : ".jks";
        File f = new File(alias + suffix);
        int count = 1;
        while (f.exists()) {
            f = new File(alias + "_" + count + suffix);
            count++;
        }

        FileOutputStream jks = new FileOutputStream(f);
        if (toPKCS8) {
            List pemItems = new LinkedList();
            PrivateKey key = (PrivateKey) ks.getKey(alias, password);
            Certificate[] chain = ks.getCertificateChain(alias);
            byte[] pkcs8DerBytes = null;
            if (key instanceof RSAPrivateCrtKey) {
                RSAPrivateCrtKey rsa = (RSAPrivateCrtKey) key;
                ASN1EncodableVector vec = new ASN1EncodableVector();
                vec.add(new DERInteger(BigInteger.ZERO));
                vec.add(new DERInteger(rsa.getModulus()));
                vec.add(new DERInteger(rsa.getPublicExponent()));
                vec.add(new DERInteger(rsa.getPrivateExponent()));
                vec.add(new DERInteger(rsa.getPrimeP()));
                vec.add(new DERInteger(rsa.getPrimeQ()));
                vec.add(new DERInteger(rsa.getPrimeExponentP()));
                vec.add(new DERInteger(rsa.getPrimeExponentQ()));
                vec.add(new DERInteger(rsa.getCrtCoefficient()));
                DERSequence seq = new DERSequence(vec);
                byte[] derBytes = PKCS8Key.encode(seq);
                PKCS8Key pkcs8 = new PKCS8Key(derBytes, null);
                pkcs8DerBytes = pkcs8.getDecryptedBytes();
            } else if (key instanceof DSAPrivateKey) {
                DSAPrivateKey dsa = (DSAPrivateKey) key;
                DSAParams params = dsa.getParams();
                BigInteger g = params.getG();
                BigInteger p = params.getP();
                BigInteger q = params.getQ();
                BigInteger x = dsa.getX();
                BigInteger y = q.modPow(x, p);

                ASN1EncodableVector vec = new ASN1EncodableVector();
                vec.add(new DERInteger(BigInteger.ZERO));
                vec.add(new DERInteger(p));
                vec.add(new DERInteger(q));
                vec.add(new DERInteger(g));
                vec.add(new DERInteger(y));
                vec.add(new DERInteger(x));
                DERSequence seq = new DERSequence(vec);
                byte[] derBytes = PKCS8Key.encode(seq);
                PKCS8Key pkcs8 = new PKCS8Key(derBytes, null);
                pkcs8DerBytes = pkcs8.getDecryptedBytes();
            }
            if (chain != null && chain.length > 0) {
                for (int i = 0; i < chain.length; i++) {
                    X509Certificate x509 = (X509Certificate) chain[i];
                    byte[] derBytes = x509.getEncoded();
                    PEMItem item = new PEMItem(derBytes, "CERTIFICATE");
                    pemItems.add(item);
                }
            }
            if (pkcs8DerBytes != null) {
                PEMItem item = new PEMItem(pkcs8DerBytes, "PRIVATE KEY");
                pemItems.add(item);
            }
            byte[] pem = PEMUtil.encode(pemItems);
            jks.write(pem);
        } else {
            ks.store(jks, password);
        }
        jks.flush();
        jks.close();
        System.out.println("Successfuly wrote: [" + f.getPath() + "]");
    }


}
