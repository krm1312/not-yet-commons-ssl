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

import javax.net.ssl.*;
import javax.net.SocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * @author Julius Davies
 * @since 30-Jun-2006
 */
public abstract class JavaImpl {
    private static JavaImpl HANDLER;

    static {
        JavaImpl h = null;
        try {
            h = Java14.getInstance();
        } catch (Throwable t) {
            System.out.println(t.toString());
            System.out.println("commons-ssl: java.net.ssl.* (Java 1.4) not available - reverting to  com.sun.net.ssl.* (Java 1.3 + jsse.jar)");
        }
        if (h == null) {
            h = Java13.getInstance();
        }
        HANDLER = h;
    }

    public static void downgrade()
    {
        if ( HANDLER instanceof Java14 )
        {
            HANDLER = Java13.getInstance();
        }
    }

    public static void uprade()
    {
        if ( HANDLER instanceof Java13 )
        {
            HANDLER = Java14.getInstance();
        }
    }

    public abstract String getVersion();

    protected abstract Object buildKeyManagerFactory(KeyStore ks, char[] pass)
            throws NoSuchAlgorithmException, KeyStoreException,
            UnrecoverableKeyException;

    protected abstract Object[] retrieveKeyManagers(Object keyManagerFactory);

    protected abstract Object buildTrustManagerFactory(KeyStore ks)
            throws NoSuchAlgorithmException, KeyStoreException;

    protected abstract Object[] retrieveTrustManagers(Object trustManagerFactory);

    protected abstract String retrieveSubjectX500(X509Certificate cert);

    protected abstract String retrieveIssuerX500(X509Certificate cert);

    protected abstract Certificate[] retrieveClientAuth(SSLSession sslSession)
            throws SSLPeerUnverifiedException;

    protected abstract SSLSocketFactory buildSSLSocketFactory(Object ssl);

    protected abstract SSLServerSocketFactory buildSSLServerSocketFactory(Object ssl);

    protected abstract SSLSocket buildSocket(SSL ssl)
            throws IOException;

    protected abstract SSLSocket buildSocket(SSL ssl, String remoteHost,
                                             int remotePort,
                                             InetAddress localHost,
                                             int localPort, int connectTimeout)
            throws IOException, UnknownHostException;

	protected abstract Socket connectSocket(Socket s, SocketFactory sf,
	                                        String remoteHost, int remotePort,
	                                        InetAddress localHost, int localPort,
	                                        int timeout)
	      throws IOException, UnknownHostException;

    protected abstract SSLServerSocket buildServerSocket(SSL ssl)
            throws IOException;

    protected abstract void wantClientAuth(Object o, boolean wantClientAuth);

    protected abstract void enabledProtocols(Object o, String[] enabledProtocols);

    protected abstract RuntimeException buildRuntimeException(Exception cause);

    protected abstract Object initSSL(SSL ssl, TrustChain tc, KeyMaterial km)
            throws NoSuchAlgorithmException, KeyStoreException,
            CertificateException, KeyManagementException, IOException;

    public static Object init(SSL ssl, TrustChain trustChain, KeyMaterial keyMaterial)
            throws NoSuchAlgorithmException, KeyStoreException,
            CertificateException, KeyManagementException, IOException {
        return HANDLER.initSSL(ssl, trustChain, keyMaterial);
    }

    public static RuntimeException newRuntimeException(Exception cause) {
        return HANDLER.buildRuntimeException(cause);
    }

    public static SSLSocketFactory getSSLSocketFactory(Object sslContext) {
        return HANDLER.buildSSLSocketFactory(sslContext);
    }

    public static SSLServerSocketFactory getSSLServerSocketFactory(Object sslContext) {
        return HANDLER.buildSSLServerSocketFactory(sslContext);
    }

    public static String getSubjectX500(X509Certificate cert) {
        return HANDLER.retrieveSubjectX500(cert);
    }

    public static String getIssuerX500(X509Certificate cert) {
        return HANDLER.retrieveIssuerX500(cert);
    }

    public static Object newKeyManagerFactory(KeyStore ks, char[] password)
            throws NoSuchAlgorithmException, KeyStoreException,
            UnrecoverableKeyException {
        return HANDLER.buildKeyManagerFactory(ks, password);
    }

    public static Object[] getKeyManagers(Object keyManagerFactory) {
        return HANDLER.retrieveKeyManagers(keyManagerFactory);
    }

    public static Object newTrustManagerFactory(KeyStore ks)
            throws NoSuchAlgorithmException, KeyStoreException {
        return HANDLER.buildTrustManagerFactory(ks);
    }

    public static Object[] getTrustManagers(Object trustManagerFactory) {
        return HANDLER.retrieveTrustManagers(trustManagerFactory);
    }

    public static SSLSocket createSocket(SSL ssl)
            throws IOException {
        return HANDLER.buildSocket(ssl);
    }

    public static SSLSocket createSocket(SSL ssl, String remoteHost,
                                         int remotePort, InetAddress localHost,
                                         int localPort, int connectTimeout)
            throws IOException, UnknownHostException {
        return HANDLER.buildSocket(ssl, remoteHost, remotePort, localHost,
                localPort, connectTimeout);
    }

	 protected static Socket connect(Socket s, SocketFactory sf,
	                                 String remoteHost, int remotePort,
	                                 InetAddress localHost, int localPort,
	                                 int timeout)
	       throws IOException, UnknownHostException
	 {
		 return HANDLER.connectSocket( s, sf, remoteHost, remotePort, localHost,
		                               localPort, timeout );		 
	 }

    public static SSLServerSocket createServerSocket(SSL ssl)
            throws IOException {
        return HANDLER.buildServerSocket(ssl);
    }

    public static void setWantClientAuth(Object o, boolean wantClientAuth) {
        HANDLER.wantClientAuth(o, wantClientAuth);
    }

    public static void setEnabledProtocols(Object o, String[] enabledProtocols) {
        HANDLER.enabledProtocols(o, enabledProtocols);
    }

    public static Certificate[] getPeerCertificates(SSLSession session)
            throws SSLPeerUnverifiedException {
        return HANDLER.retrieveClientAuth(session);
    }

    public static void load() {
        HANDLER.hashCode();
    }

}
