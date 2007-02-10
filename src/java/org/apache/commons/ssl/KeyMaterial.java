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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 27-Feb-2006
 */
public class KeyMaterial extends TrustMaterial
{
	private Object keyManagerFactory;
	private String alias;
	private X509Certificate[] associatedChain;

	public KeyMaterial( InputStream jks, char[] password )
			throws GeneralSecurityException, IOException
	{
		this( Util.streamToBytes( jks ), password );
	}

	public KeyMaterial( InputStream jks, InputStream key, char[] password )
			throws GeneralSecurityException, IOException
	{
		this( jks != null ? Util.streamToBytes( jks ) : null,
		      key != null ? Util.streamToBytes( key ) : null,
		      password );
	}

	public KeyMaterial( String pathToJksFile, char[] password )
			throws GeneralSecurityException, IOException
	{
		this( new File( pathToJksFile ), password );
	}

	public KeyMaterial( String pathToCerts, String pathToKey, char[] password )
			throws GeneralSecurityException, IOException
	{
		this( pathToCerts != null ? new File( pathToCerts ) : null,
		      pathToKey != null ? new File( pathToKey ) : null,
		      password );
	}

	public KeyMaterial( File jksFile, char[] password )
			throws GeneralSecurityException, IOException
	{
		this( new FileInputStream( jksFile ), password );
	}

	public KeyMaterial( File certsFile, File keyFile, char[] password )
			throws GeneralSecurityException, IOException
	{
		this( certsFile != null ? new FileInputStream( certsFile ) : null,
		      keyFile != null ? new FileInputStream( keyFile ) : null,
		      password );
	}


	public KeyMaterial( URL urlToJKS, char[] password )
			throws GeneralSecurityException, IOException
	{
		this( urlToJKS.openStream(), password );
	}

	public KeyMaterial( URL urlToCerts, URL urlToKey, char[] password )
			throws GeneralSecurityException, IOException
	{
		this( urlToCerts.openStream(), urlToKey.openStream(), password );
	}

	public KeyMaterial( byte[] jks, char[] password )
			throws GeneralSecurityException, IOException
	{
		this( jks, null, password );
	}

	public KeyMaterial( byte[] jksOrCerts, byte[] key, char[] password )
			throws GeneralSecurityException, IOException
	{
		// We're not a simple trust type, so set "simpleTrustType" value to 0.
		// Only TRUST_ALL and TRUST_THIS_JVM are simple trust types.
		super( KeyStoreBuilder.build( jksOrCerts, key, password ), 0 );
		KeyStore ks = getKeyStore();
		Enumeration en = ks.aliases();
		int privateKeyCount = 0;
		while ( en.hasMoreElements() )
		{
			String alias = (String) en.nextElement();
			if ( ks.isKeyEntry( alias ) )
			{
				privateKeyCount++;
				if ( privateKeyCount > 1 )
				{
					throw new KeyStoreException( "commons-ssl KeyMaterial only supports keystores with a single private key." );
				}
				this.alias = alias;
			}
		}
		if ( alias != null )
		{
			Certificate[] chain = ks.getCertificateChain( alias );
			if ( chain != null )
			{
				X509Certificate[] x509Chain = new X509Certificate[chain.length];
				for ( int i = 0; i < chain.length; i++ )
				{
					x509Chain[ i ] = (X509Certificate) chain[ i ];
				}
				this.associatedChain = x509Chain;
			}
			else
			{
				// is password wrong?
			}
		}
		this.keyManagerFactory = JavaImpl.newKeyManagerFactory( ks, password );
	}

	public Object[] getKeyManagers()
	{
		return JavaImpl.getKeyManagers( keyManagerFactory );
	}

	public X509Certificate[] getAssociatedCertificateChain()
	{
		return associatedChain;
	}

	public KeyStore getKeyStore()
	{
		return super.getKeyStore();
	}

	public String getAlias()
	{
		return alias;
	}

	public static void main( String[] args ) throws Exception
	{
		if ( args.length < 2 )
		{
			System.out.println( "Usage:  java org.apache.commons.ssl.KeyMaterial [client-cert] [password]" );
			System.exit( 1 );
		}
		String keypath = args[ 0 ];
		char[] password = args[ 1 ].toCharArray();
		KeyMaterial km = new KeyMaterial( keypath, password );
		System.out.println( km );
	}

	public String toString()
	{
		X509Certificate[] certs = getAssociatedCertificateChain();
		StringBuffer buf = new StringBuffer( 1024 );
		buf.append( "Alias: " );
		buf.append( alias );
		buf.append( '\n' );
		if ( certs != null )
		{
			for ( int i = 0; i < certs.length; i++ )
			{
				buf.append( Certificates.toString( certs[ i ] ) );
				try
				{
					buf.append( Certificates.toPEMString( certs[ i ] ) );
				}
				catch ( CertificateEncodingException cee )
				{
					buf.append( cee.toString() );
					buf.append( '\n' );
				}
			}
		}
		return buf.toString();
	}
}
