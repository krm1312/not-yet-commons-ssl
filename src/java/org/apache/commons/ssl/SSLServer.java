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

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Properties;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since May 1, 2006
 */
public class SSLServer extends SSLServerSocketFactory
{
	protected final SSL ssl;

	public SSLServer()
			throws GeneralSecurityException, IOException
	{
		this.ssl = new SSL();
		// client certs aren't usually tied down to a single host (and who knows
		// if the DNS reverse-lookup will work!).
		setCheckHostname( false );

		// If running inside Tomcat, let's try to re-use Tomcat's SSL certificate
		// for our own stuff (e.g. RMI-SSL). 
		Integer p8443 = new Integer( 8443 );
		KeyMaterial km;
		TrustMaterial tm;
		km = (KeyMaterial) TomcatServerXML.KEY_MATERIAL_BY_PORT.get( p8443 );
		tm = (TrustMaterial) TomcatServerXML.TRUST_MATERIAL_BY_PORT.get( p8443 );

		// If 8443 isn't set, let's take lowest secure port.
		km = km == null ? TomcatServerXML.KEY_MATERIAL : km;
		tm = tm == null ? TomcatServerXML.TRUST_MATERIAL : tm;
		if ( km != null )
		{
			setKeyMaterial( km );
			if ( tm != null && !TrustMaterial.DEFAULT.equals( tm ) )
			{
				setTrustMaterial( tm );
			}
		}
		else
		{
			// If we're not able to re-use Tomcat's SSLServerSocket configuration,
			// commons-ssl default KeyMaterial will be ~/.keystore with a password
			// of "changeit".
			Properties props = System.getProperties();
			boolean pwdSet = props.containsKey( "javax.net.ssl.keyStorePassword" );
			String pwd = props.getProperty( "javax.net.ssl.keyStorePassword" );
			pwd = pwdSet ? pwd : "changeit";

			// If "javax.net.ssl.keyStore" is set, then we won't bother with this
			// silly SSLServer default behaviour.
			if ( !ssl.usingSystemProperties )
			{
				String userHome = System.getProperty( "user.home" );
				String path = userHome + "/.keystore";
				File f = new File( path );
				if ( f.exists() )
				{
					try
					{
						km = new KeyMaterial( path, pwd.toCharArray() );
						setKeyMaterial( km );
					}
					catch ( Exception e )
					{
						// Don't want to blowup just because this silly default
						// behaviour didn't work out.
						if ( pwdSet )
						{
							// Buf if the user has specified a non-standard password for
							// "javax.net.ssl.keyStorePassword", then we will warn them
							// that things didn't work out.
							System.out.println( "commons-ssl automatic loading of [" + path + "] failed. " );
							System.out.println( e );
						}
					}
				}
			}
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

	public void setCheckExpiry( boolean checkExpiry )
	{
		ssl.setCheckExpiry( checkExpiry );
	}

	public boolean getCheckExpiry()
	{
		return ssl.getCheckExpiry();
	}

	public void setCheckHostname( boolean checkHostname )
	{
		ssl.setCheckHostname( checkHostname );
	}

	public boolean getCheckHostname()
	{
		return ssl.getCheckHostname();
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

	public TrustChain getTrustChain()
	{
		return ssl.getTrustChain();
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

	public boolean getWantClientAuth()
	{
		return ssl.getWantClientAuth();
	}

	public boolean getNeedClientAuth()
	{
		return ssl.getNeedClientAuth();
	}

	public SSLWrapperFactory getSSLWrapperFactory()
	{
		return ssl.getSSLWrapperFactory();
	}

	public void setSSLWrapperFactory( SSLWrapperFactory wf )
	{
		ssl.setSSLWrapperFactory( wf );
	}

	public SSLContext getSSLContext()
			throws GeneralSecurityException, IOException
	{
		return ssl.getSSLContext();
	}

	public ServerSocket createServerSocket() throws IOException
	{
		return ssl.createServerSocket();
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
		return ssl.createServerSocket( port, backlog, localHost );
	}

	public X509Certificate[] getCurrentClientChain()
	{
		return ssl.getCurrentClientChain();
	}


}
