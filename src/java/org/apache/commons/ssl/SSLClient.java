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

import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 27-Feb-2006
 */
public class SSLClient extends SSLSocketFactory
{

	private final SSL ssl;

	public SSLClient()
			throws GeneralSecurityException, IOException
	{
		this.ssl = new SSL();
	}

	public void addTrustMaterial( TrustChain trustChain )
			throws NoSuchAlgorithmException, KeyStoreException,
			       KeyManagementException, IOException, CertificateException
	{
		ssl.addTrustMaterial( trustChain );
	}

	public void setTrustMaterial( TrustChain trustChain )
			throws NoSuchAlgorithmException, KeyStoreException,
			       KeyManagementException, IOException, CertificateException
	{
		ssl.setTrustMaterial( trustChain );
	}

	public void setKeyMaterial( KeyMaterial keyMaterial )
			throws NoSuchAlgorithmException, KeyStoreException,
			       KeyManagementException, IOException, CertificateException
	{
		ssl.setKeyMaterial( keyMaterial );
	}

	public String[] getEnabledCiphers()
	{
		return ssl.getEnabledCiphers();
	}

	public void setEnabledCiphers( String[] ciphers )
			throws IllegalArgumentException
	{
		ssl.setEnabledCiphers( ciphers );
	}

	public String[] getEnabledProtocols()
	{
		return ssl.getEnabledProtocols();
	}

	public void setEnabledProtocols( String[] protocols )
	{
		ssl.setEnabledProtocols( protocols );
	}

	public void setDoVerify( boolean doVerify )
	{
		ssl.setDoVerify( doVerify );
	}

	public boolean getDoVerify()
	{
		return ssl.getDoVerify();
	}

	public X509Certificate[] getAssociatedCertificateChain()
	{
		return ssl.getAssociatedCertificateChain();
	}

	public void setCheckCRL( boolean checkCRL )
	{
		ssl.setCheckCRL( checkCRL );
	}

	public boolean getCheckCRL()
	{
		return ssl.getCheckCRL();
	}

	public void setSoTimeout( int soTimeout )
	{
		ssl.setSoTimeout( soTimeout );
	}

	public void setUseClientMode( boolean useClientMode )
	{
		ssl.setUseClientMode( useClientMode );
	}

	public void setConnectTimeout( int connectTimeout )
	{
		ssl.setConnectTimeout( connectTimeout );
	}

	public void setDefaultProtocol( String protocol )
	{
		ssl.setDefaultProtocol( protocol );
	}

	public String[] getDefaultCipherSuites()
	{
		return ssl.getDefaultCipherSuites();
	}

	public String[] getSupportedCipherSuites()
	{
		return ssl.getSupportedCipherSuites();
	}

	public TrustChain getTrustChain()
	{
		return ssl.getTrustChain();
	}

	public SSLWrapperFactory getSSLWrapperFactory()
	{
		return ssl.getSSLWrapperFactory();
	}

	public void setSSLWrapperFactory( SSLWrapperFactory wf )
	{
		ssl.setSSLWrapperFactory( wf );
	}


	public Socket createSocket() throws IOException
	{
		return ssl.createSocket();
	}

	public Socket createSocket( String host, int port )
			throws IOException
	{
		return ssl.createSocket( host, port );
	}

	public Socket createSocket( InetAddress host, int port )
			throws IOException
	{
		return createSocket( host.getHostName(), port );
	}

	public Socket createSocket( InetAddress host, int port,
	                            InetAddress localHost, int localPort )
			throws IOException
	{
		return createSocket( host.getHostName(), port, localHost, localPort );
	}

	public Socket createSocket( String host,
	                            int port,
	                            InetAddress localHost,
	                            int localPort )
			throws IOException
	{
		return createSocket( host, port, localHost, localPort, 0 );
	}

	/**
	 * Attempts to get a new socket connection to the given host within the
	 * given time limit.
	 *
	 * @param host      the host name/IP
	 * @param port      the port on the host
	 * @param localHost the local host name/IP to bind the socket to
	 * @param localPort the port on the local machine
	 * @param timeout   the connection timeout (0==infinite)
	 * @return Socket a new socket
	 * @throws IOException          if an I/O error occurs while creating thesocket
	 * @throws UnknownHostException if the IP address of the host cannot be
	 *                              determined
	 */
	public Socket createSocket( String host, int port, InetAddress localHost,
	                            int localPort, int timeout )
			throws IOException
	{
		return ssl.createSocket( host, port, localHost, localPort, timeout );
	}

	public Socket createSocket( Socket s, String remoteHost, int remotePort,
	                            boolean autoClose )
			throws IOException
	{
		return ssl.createSocket( s, remoteHost, remotePort, autoClose );
	}

	public X509Certificate[] getCurrentServerChain()
	{
		return ssl.getCurrentServerChain();
	}

}
