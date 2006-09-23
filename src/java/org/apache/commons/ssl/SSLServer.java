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

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since May 1, 2006
 */
public class SSLServer extends SSLServerSocketFactory
{

	private final SSL ssl;

	public SSLServer()
	      throws NoSuchAlgorithmException, KeyStoreException,
	             KeyManagementException, IOException, CertificateException
	{
		this.ssl = new SSL();

		String keystore = System.getProperty( "javax.net.ssl.keyStore" );
		String password = System.getProperty( "javax.net.ssl.keyStorePassword" );
		if ( keystore == null )
		{
			String homeDir = System.getProperty( "user.home" );
			keystore = homeDir + "/.keystore";
		}
		if ( password == null )
		{
			password = "changeit";
		}

		KeyMaterial km = null;
		try
		{
			km = new KeyMaterial( keystore, password.toCharArray() );
		}
		catch ( Exception e )
		{
			if ( !password.equals( "changeit" ) )
			{
System.out.println( "commons-ssl attempt to automatically load " + keystore + " failed " );
System.out.println( e );
			}
		}

		if ( km != null )
		{
			setKeyMaterial( km );
		}
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

	public X509Certificate[] getAssociatedCertificateChain()
	{
		return ssl.getAssociatedCertificateChain();
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

	public void setSoTimeout( int soTimeout )
	{
		ssl.setSoTimeout( soTimeout );
	}

	public String[] getDefaultCipherSuites()
	{
		return ssl.getDefaultCipherSuites();
	}

	public String[] getSupportedCipherSuites()
	{
		return ssl.getSupportedCipherSuites();
	}

	public void setWantClientAuth( boolean wantClientAuth )
	{
		ssl.setWantClientAuth( wantClientAuth );
	}

	public void setNeedClientAuth( boolean needClientAuth )
	{
		ssl.setNeedClientAuth( needClientAuth );
	}

	public SSLWrapperFactory getSSLWrapperFactory()
	{
		return ssl.getSSLWrapperFactory();
	}

	public void setSSLWrapperFactory( SSLWrapperFactory wf )
	{
		ssl.setSSLWrapperFactory( wf );
	}

	public ServerSocket createServerSocket() throws IOException
	{
		SSLServerSocket ss = JavaImpl.createServerSocket( ssl );
		return ssl.getSSLWrapperFactory().wrap( ss );
	}

	public ServerSocket createServerSocket( int port )
	      throws IOException
	{
		return createServerSocket( port, 50 );
	}

	public ServerSocket createServerSocket( int port, int backlog )
	      throws IOException
	{
		return createServerSocket( port, backlog, null );
	}

	/**
	 * Attempts to get a new socket connection to the given host within the
	 * given time limit.
	 *
	 * @param localHost the local host name/IP to bind against (null == ANY)
	 * @param port      the port to listen on
	 * @param backlog   number of connections allowed to queue up for accept().
	 * @return SSLServerSocket a new server socket
	 * @throws IOException if an I/O error occurs while creating thesocket
	 */
	public ServerSocket createServerSocket( int port, int backlog,
	                                        InetAddress localHost )
	      throws IOException
	{
		SSLServerSocketFactory f = ssl.getSSLServerSocketFactory();
		ServerSocket ss = f.createServerSocket( port, backlog, localHost );
		SSLServerSocket s = (SSLServerSocket) ss;
		ssl.doPreConnectServerSocketStuff( s );
		return ssl.getSSLWrapperFactory().wrap( s );
	}

	public X509Certificate[] getCurrentClientChain()
	{
		return ssl.getCurrentClientChain();
	}


}
