package org.apache.commons.ssl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

/**
 * @author julius
 * @since 4-Nov-2006
 */
public class KeyStoreBuilder
{
	private final static CertificateFactory CF;

	static
	{
		CertificateFactory cf;
		try
		{
			cf = CertificateFactory.getInstance( "X.509" );
		}
		catch ( CertificateException ce )
		{
			// we're screwed
			throw new RuntimeException( ce );
		}
		CF = cf;
	}

	public static KeyStore build( byte[] jksOrCerts, char[] password )
			throws IOException
	{
		return build( jksOrCerts, null, password );
	}

	public static KeyStore build( byte[] jksOrCerts, byte[] privateKey,
	                              char[] password ) throws IOException
	{
		List pemItems = PEMUtil.decode( jksOrCerts );
		LinkedList certs = new LinkedList();
		if ( !pemItems.isEmpty() )
		{
			Iterator it = pemItems.iterator();
			while ( it.hasNext() )
			{
				PEMItem item = (PEMItem) it.next();
				byte[] derBytes = item.getDerBytes();
				ByteArrayInputStream in = new ByteArrayInputStream( derBytes );
				try
				{
					Certificate cert = CF.generateCertificate( in );
					X509Certificate x509 = (X509Certificate) cert;
System.out.println( Certificates.toString( x509 ) );					
					certs.add( x509 );
				}
				catch ( CertificateException ce )
				{
System.out.println( ce );
				}
			}
		}


		return null;
	}


	public static void main( String[] args ) throws Exception
	{
		FileInputStream fin = new FileInputStream( args[ 0 ] );
		byte[] bytes = Util.streamToBytes( fin );
		build( bytes, null );
	}


}
