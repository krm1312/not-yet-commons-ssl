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

import org.apache.commons.httpclient.params.HttpConnectionParams;
import org.apache.commons.httpclient.protocol.SecureProtocolSocketFactory;
import org.apache.http.conn.scheme.LayeredSocketFactory;

import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;

/**
 * Hook into HttpClient.
 *
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 5-May-2006
 */
public class HttpSecureProtocol extends SSLClient
    implements SecureProtocolSocketFactory, LayeredSocketFactory {

    public HttpSecureProtocol()
        throws GeneralSecurityException, IOException {
        super();
    }

    /**
     * Attempts to get a new socket connection to the given host within the
     * given time limit.
     * <p/>
     * To circumvent the limitations of older JREs that do not support connect
     * timeout a controller thread is executed. The controller thread attempts
     * to create a new socket within the given limit of time. If socket
     * constructor does not return until the timeout expires, the controller
     * terminates and throws an
     * {@link org.apache.commons.httpclient.ConnectTimeoutException}
     * </p>
     *
     * @param host         the host name/IP
     * @param port         the port on the host
     * @param localAddress the local host name/IP to bind the socket to
     * @param localPort    the port on the local machine
     * @param params       {@link org.apache.commons.httpclient.params.HttpConnectionParams Http connection parameters}
     * @return Socket a new socket
     * @throws java.io.IOException           if an I/O error occurs while creating the socket
     * @throws java.net.UnknownHostException if the IP address of the host cannot be
     *                                       determined
     */
    public Socket createSocket(final String host,
                               final int port,
                               final InetAddress localAddress,
                               final int localPort,
                               final HttpConnectionParams params)
        throws IOException {
        if (params == null) {
            throw new IllegalArgumentException("Parameters may not be null");
        }
        int timeout = params.getConnectionTimeout();
        return super.createSocket(host, port, localAddress, localPort, timeout);
    }

    public java.net.Socket createSocket(
        Socket socket, String host, int port, boolean autoClose
    ) throws java.io.IOException, java.net.UnknownHostException {

        // Julius Davies:  this is redundant, but I wanted to keep an eye
        // on the HttpComponents LayeredSocketFactory interface.
        
        return super.createSocket(socket, host, port, autoClose);
    }

    public java.net.Socket connectSocket(
        Socket sock, String host, int port, InetAddress localAddress, int localPort, org.apache.http.params.HttpParams params
    ) throws IOException, UnknownHostException, org.apache.http.conn.ConnectTimeoutException {

        // Ugh where the did this provided socket come from?
        // My quick review of HttpClient 4.x's own SSLSocketFactory
        // gives me the idea to just ignore it (cross fingers)
        // since it's probably just a new SSLSocket() [empty constructor].

        int timeout = org.apache.http.params.HttpConnectionParams.getConnectionTimeout(params);
        return super.createSocket(host, port, localAddress, localPort, timeout);
    }

    public boolean isSecure(Socket sock) throws IllegalArgumentException {

        // These 3 checkx below are copied directly from org/apache/http/conn/ssl/SSLSocketFactory.java.
        // http://svn.apache.org/viewvc?view=revision&revision=498143
        // Original author: Roland Weber, rolandw@apache.org, ossfwot@dubioso.net
        // Copied by Julius Davies, November 11th, 2009

        if (sock == null) { throw new IllegalArgumentException("Socket may not be null."); }
        if (!(sock instanceof SSLSocket)) { throw new IllegalArgumentException("Socket not created by this factory."); }
        if (sock.isClosed()) { throw new IllegalArgumentException("Socket is closed."); }

        // Back to Julius Davies code.  :-)
        return sock instanceof SSLSocket || isSecure();
    }

}
