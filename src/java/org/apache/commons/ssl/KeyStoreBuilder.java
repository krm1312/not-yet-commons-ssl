package org.apache.commons.ssl;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

/**
 * Builds Java Key Store files out of pkcs12 files, or out of pkcs8 files +
 * certificate chains.  Also supports OpenSSL style private keys (encrypted or
 * unencrypted).
 *
 * @author Julius Davies
 * @since 4-Nov-2006
 */
public class KeyStoreBuilder
{
	public static KeyStore build( byte[] jksOrCerts, char[] password )
			throws IOException, CertificateException, KeyStoreException,
			       NoSuchAlgorithmException
	{
		return build( jksOrCerts, null, password );
	}

	public static KeyStore build( byte[] jksOrCerts, byte[] privateKey,
	                              char[] password )
			throws IOException, CertificateException, KeyStoreException,
			       NoSuchAlgorithmException
	{
		BuildResult br1 = parse( jksOrCerts, password );
		Key key = br1.key;
		Certificate[] chain = br1.chain;

		boolean atLeastOneNotSet = key == null || chain == null;
		if ( atLeastOneNotSet && privateKey != null )
		{
			BuildResult br2 = parse( privateKey, password );
			if ( key == null )
			{
				key = br2.key;
			}
			if ( br2.chain != null )
			{
				chain = br2.chain;
			}
		}

		atLeastOneNotSet = key == null || chain == null;
		if ( atLeastOneNotSet )
		{
			String missing = "";
			if ( key == null )
			{
				missing = " [Private key missing]";
			}
			if ( chain == null )
			{
				missing += " [Certificate chain missing]";
			}
			throw new KeyStoreException( "Can't build keystore:" + missing );
		}
		else
		{
			String alias = null;
			if ( key instanceof RSAPrivateCrtKey )
			{
				final RSAPrivateCrtKey rsa = (RSAPrivateCrtKey) key;
				BigInteger publicExponent = rsa.getPublicExponent();
				BigInteger modulus = rsa.getModulus();
				for ( int i = 0; i < chain.length; i++ )
				{
					X509Certificate c = (X509Certificate) chain[ i ];
					PublicKey pub = c.getPublicKey();
					if ( pub instanceof RSAPublicKey )
					{
						RSAPublicKey certKey = (RSAPublicKey) pub;
						BigInteger pe = certKey.getPublicExponent();
						BigInteger mod = certKey.getModulus();
						if ( publicExponent.equals( pe ) && modulus.equals( mod ) )
						{
							alias = Certificates.getCN( c );
						}
					}
				}
				if ( alias == null )
				{
					throw new KeyStoreException( "Can't build keystore: [No certificates belong to the private-key]" );
				}
			}

			KeyStore ks = KeyStore.getInstance( "jks" );
			ks.load( null, password );
			ks.setKeyEntry( alias, key, password, chain );
			return ks;
		}
	}

	protected static class BuildResult
	{
		protected final Key key;
		protected final Certificate[] chain;
		protected final KeyStore jks;

		protected BuildResult( Key key, Certificate[] chain, KeyStore jks )
		{
			this.key = key;
			this.chain = chain;
			this.jks = jks;
		}
	}


	public static BuildResult parse( byte[] stuff, char[] password )
			throws IOException, CertificateException, KeyStoreException
	{
		CertificateFactory cf = CertificateFactory.getInstance( "X.509" );
		Key key = null;
		Certificate[] chain = null;
		KeyStore jks = null;
		try
		{
			PKCS8Key pkcs8Key = new PKCS8Key( stuff, password );
			key = pkcs8Key.getPrivateKey();
		}
		catch ( Exception e )
		{
			// no luck
		}

		ByteArrayInputStream stuffStream = new ByteArrayInputStream( stuff );
		List certificates = new LinkedList();
		List pemItems = PEMUtil.decode( stuff );
		Iterator it = pemItems.iterator();
		while ( it.hasNext() )
		{
			PEMItem item = (PEMItem) it.next();
			byte[] derBytes = item.getDerBytes();
			String type = item.pemType.trim().toUpperCase();
			if ( type.startsWith( "CERT" ) )
			{
				ByteArrayInputStream in = new ByteArrayInputStream( derBytes );
				X509Certificate c = (X509Certificate) cf.generateCertificate( in );
				certificates.add( c );
			}
		}

		if ( key == null && certificates.isEmpty() )
		{
			stuffStream.reset();

			// Okay, so far no luck.  Maybe it's an ASN.1 DER stream of
			// certificates?
			try
			{
				Collection certs = cf.generateCertificates( stuffStream );
				it = certs.iterator();
				while ( it.hasNext() )
				{
					X509Certificate x509 = (X509Certificate) it.next();
					certificates.add( x509 );
				}
			}
			catch ( CertificateException ce )
			{
				// oh well
			}
		}

		if ( key == null && certificates.isEmpty() )
		{
			stuffStream.reset();

			// Okay, still no luck.  Maybe it's an ASN.1 DER stream containing only
			// a single certificate?
			try
			{
				Certificate c = cf.generateCertificate( stuffStream );
				X509Certificate x509 = (X509Certificate) c;
				certificates.add( x509 );
			}
			catch ( CertificateException ce )
			{
				// oh well
			}
		}

		if ( certificates.isEmpty() )
		{
			if ( key == null )
			{
				stuffStream.reset();
				// So far no parsing luck.  Let's try for PKCS12
				KeyStore pkcs12KeyStore = KeyStore.getInstance( "pkcs12" );
				try
				{
					pkcs12KeyStore.load( stuffStream, password );
					Enumeration en = pkcs12KeyStore.aliases();
					while ( en.hasMoreElements() )
					{
						String alias = (String) en.nextElement();
						if ( pkcs12KeyStore.isKeyEntry( alias ) )
						{
							key = pkcs12KeyStore.getKey( alias, password );
							if ( key != null )
							{
								chain = pkcs12KeyStore.getCertificateChain( alias );
								break;
							}
						}
						if ( en.hasMoreElements() )
						{
							System.out.println( "what kind of weird pkcs12 file has more than one alias?" );
						}
					}
				}
				catch ( GeneralSecurityException e )
				{
					// pkcs12 didn't work.
				}
				catch ( IOException ioe )
				{
					// pkcs12 didn't work.
				}
			}

			if ( key == null )
			{
				stuffStream.reset();

				// So far no parsing luck.  Let's try for JKS.
				KeyStore jksKeyStore = KeyStore.getInstance( "jks" );
				try
				{
					jksKeyStore.load( stuffStream, password );
					Enumeration en = jksKeyStore.aliases();
					while ( en.hasMoreElements() )
					{
						String alias = (String) en.nextElement();
						if ( jksKeyStore.isKeyEntry( alias ) )
						{
							key = jksKeyStore.getKey( alias, password );
							// With JKS we're only interested in PrivateKeys.
							// All others will be ignored.
							if ( key != null && key instanceof PrivateKey )
							{
								chain = jksKeyStore.getCertificateChain( alias );
								break;
							}
						}
					}
					jks = jksKeyStore;
				}
				catch ( GeneralSecurityException gse )
				{
					// jks didn't work.
				}
				catch ( IOException ioe )
				{
					// pkcs12 didn't work.
				}
			}
		}
		else
		{
			int certsFound = certificates.size();
			X509Certificate[] x509Chain = new X509Certificate[certsFound];
			certificates.toArray( x509Chain );
			chain = x509Chain;
		}

		return new BuildResult( key, chain, jks );
	}


	public static void main( String[] args ) throws Exception
	{
		if ( args.length < 2 )
		{
			System.out.println( "KeyStoreBuilder:  outputs JKS file (java keystore) as ./[alias].jks" );
			System.out.println( "[alias] will be set to the first CN value of the X509 certificate." );
			System.out.println( "-------------------------------------------------------------------" );
			System.out.println( "Usage1:  [password] [file:pkcs12]" );
			System.out.println( "Usage2:  [password] [file:private-key] [file:certificate-chain]" );
			System.out.println( "-------------------------------------------------------------------" );
			System.out.println( "[private-key] can be openssl format, or pkcs8." );
			System.out.println( "[password] decrypts [private-key], and also encrypts outputted JKS file." );
			System.out.println( "All files can be PEM or DER." );
			System.exit( 1 );
		}
		char[] password = args[ 0 ].toCharArray();
		FileInputStream fin1 = new FileInputStream( args[ 1 ] );
		byte[] bytes1 = Util.streamToBytes( fin1 );
		byte[] bytes2 = null;
		if ( args[ 2 ] != null )
		{
			FileInputStream fin2 = new FileInputStream( args[ 2 ] );
			bytes2 = Util.streamToBytes( fin2 );
		}

		KeyStore ks = build( bytes1, bytes2, password );
		Enumeration en = ks.aliases();
		String alias = null;
		while ( en.hasMoreElements() )
		{
			if ( alias == null )
			{
				alias = (String) en.nextElement();
			}
			else
			{
				System.out.println( "Generated keystore contains more than 1 alias!?!?" );
			}
		}

		File f = new File( alias + ".jks" );
		int count = 1;
		while ( f.exists() )
		{
			f = new File( alias + "_" + count + ".jks" );
			count++;
		}

		FileOutputStream jks = new FileOutputStream( f );
		ks.store( jks, password );
		jks.flush();
		jks.close();
		System.out.println( "Successfuly wrote: " + f.getPath() );
	}


}
