package org.apache.commons.ssl;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.pkcs.RSAPrivateKeyStructure;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * @author julius
 * @since 4-Nov-2006
 */
public class KeyStoreBuilder
{
	private final static CertificateFactory CF;
	private final static KeyFactory KF;
	public final static Map PRIVATE_KEY_TYPES;

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

		KeyFactory kf;
		try
		{
			kf = KeyFactory.getInstance( "RSA" );
		}
		catch ( NoSuchAlgorithmException nsae )
		{
			// are we screwed?
			throw new RuntimeException( nsae );
		}
		KF = kf;

		Map m = new TreeMap();
		m.put( "RSA PRIVATE KEY", "ssleay-traditional" );
		m.put( "PRIVATE KEY", "pkcs8-unencrypted" );
		m.put( "ENCRYPTED PRIVATE KEY", "pkcs8-encrypted" );
		// m.put( "CERTIFICATE", "x509-unencrypted" );
		PRIVATE_KEY_TYPES = Collections.unmodifiableMap( m );
	}

	public static KeyStore build( byte[] jksOrCerts, char[] password )
			throws IOException
	{
		return build( jksOrCerts, null, password );
	}

	private static class BuildResult
	{
		protected List certs = new LinkedList();
		protected PEMItem privatePEMItem;
	}

	public static KeyStore build( byte[] jksOrCerts, byte[] privateKey,
	                              char[] password ) throws IOException
	{
		tryCertsAsPEM( jksOrCerts, password );
		// tryKeyIsPEM( privateKey, password );

		return null;
	}

	private static BuildResult tryCertsAsPEM( byte[] jksOrCerts,
	                                          char[] password )
			throws IOException
	{
		List pemItems = PEMUtil.decode( jksOrCerts );
		BuildResult br = new BuildResult();
		PEMItem privateKey = null;
		if ( !pemItems.isEmpty() )
		{
			Iterator it = pemItems.iterator();
			while ( it.hasNext() )
			{
				PEMItem item = (PEMItem) it.next();
				String pemType = item.pemType;
				if ( pemType.startsWith( "CERT" ) )
				{
					it.remove();
					byte[] derBytes = item.getDerBytes();
					ByteArrayInputStream in = new ByteArrayInputStream( derBytes );
					try
					{
						Certificate cert = CF.generateCertificate( in );
						X509Certificate x509 = (X509Certificate) cert;
						br.certs.add( x509 );
						System.out.println( Certificates.toString( x509 ) );
					}
					catch ( CertificateException ce )
					{
						System.out.println( "Failed to parse " + item.pemType + ": " + ce );
					}
				}
				else if ( PRIVATE_KEY_TYPES.containsKey( pemType ) )
				{
					if ( privateKey == null )
					{
						it.remove();
						privateKey = item;
					}
					else
					{
						throw new RuntimeException( "too many private keys!" );
					}
				}
			}
		}
		if ( privateKey != null )
		{
			KeySpec spec = null;
			String pemType = privateKey.pemType;
			byte[] bytes = privateKey.getDerBytes();
			String type = (String) PRIVATE_KEY_TYPES.get( pemType );
			System.out.println( pemType + ":" + type );
			if ( "pkcs8-unencrypted".equals( type ) )
			{
				spec = new PKCS8EncodedKeySpec( bytes );
			}
			else if ( "pkcs8-encrypted".equals( type ) )
			{
				EncryptedPrivateKeyInfo epki = new EncryptedPrivateKeyInfo( bytes );
				AlgorithmParameters params = epki.getAlgParameters();
				String alg = epki.getAlgName();
				if ( !alg.startsWith( "1." ) && params != null )
				{
					try
					{
						PBEKeySpec pbe = new PBEKeySpec( password );
						SecretKeyFactory skf = SecretKeyFactory.getInstance( alg );
						SecretKey sk = skf.generateSecret( pbe );
						Cipher c = Cipher.getInstance( alg );
						c.init( Cipher.DECRYPT_MODE, sk, params );
						spec = epki.getKeySpec( c );
					}
					catch ( Exception e )
					{
						System.out.println( e );
					}
				}
				else
				{
					System.out.println( "Don't know how to deal with this pkcs8 encrypted key." );
					System.out.println( "Try a different provider / JVM  (Sun-Java5 default provider can only handle pkcs8 v1.5)" );
				}
			}
			else
			{
				byte[] rsaKey = null;
				// ssleay format used by openssl!
				if ( "UNKNOWN".equals( privateKey.cipher ) )
				{
					System.out.println( "old style ssleay not encrypted" );
					rsaKey = bytes;
				}
				else
				{
					String cipher = privateKey.cipher;
					String mode = privateKey.mode;
					byte[] iv = privateKey.iv;
					int keySize = privateKey.keySizeInBits;
					String transformation = cipher + "/" + mode + "/PKCS5Padding";

					byte[] key = ssleayCreateKey( password, iv, keySize );
					SecretKey sk = new SecretKeySpec( key, cipher );
					IvParameterSpec ivParams = new IvParameterSpec( iv );

					try
					{
						Cipher c = Cipher.getInstance( transformation );
						c.init( Cipher.DECRYPT_MODE, sk, ivParams );
						InputStream in = new ByteArrayInputStream( bytes );
						in = new CipherInputStream( in, c );
						rsaKey = Util.streamToBytes( in );
					}
					catch ( GeneralSecurityException gse )
					{
						System.out.println( "couldn't decrypt SSLEAY format rsa key: " + gse );
					}
				}

				ASN1InputStream in = new ASN1InputStream( rsaKey );
				DERObject obj = in.readObject();
				ASN1Sequence seq = (ASN1Sequence) obj;
				RSAPrivateKeyStructure rsa = new RSAPrivateKeyStructure( seq );
				spec = new KeyHelper.RSAPrivateCrtKeyImpl( rsa.getModulus(),
				                                           rsa.getPublicExponent(),
				                                           rsa.getPrivateExponent(),
				                                           rsa.getPrime1(),
				                                           rsa.getPrime2(),
				                                           rsa.getExponent1(),
				                                           rsa.getExponent2(),
				                                           rsa.getCoefficient() );

			}

			PrivateKey pk = null;
			try
			{
				pk = KF.generatePrivate( spec );
			}
			catch ( InvalidKeySpecException ikse )
			{
				ikse.printStackTrace( System.out );
			}

			if ( pk != null )
			{
				System.out.println( PEMUtil.formatRSAPrivateKey( (RSAPrivateCrtKey) pk ) );
				System.out.println( Certificates.toString( pk.getEncoded() ) );
			}

		}


		return null;


	}

	public static byte[] ssleayCreateKey( char[] password, byte[] salt,
	                                      int keySizeInBits )
	{
		byte[] key = new byte[keySizeInBits / 8];

		MessageDigest md5;
		try
		{
			md5 = MessageDigest.getInstance( "MD5" );
			md5.reset();
		}
		catch ( NoSuchAlgorithmException nsae )
		{
			throw new RuntimeException( nsae );
		}

		byte[] pwd = new byte[password.length];
		for ( int i = 0; i < pwd.length; i++ )
		{
			pwd[ i ] = (byte) password[ i ];
		}
		int currentPos = 0;
		while ( currentPos < key.length )
		{
			md5.update( pwd );
			md5.update( salt, 0, 8 );  // First 8 bytes of salt ONLY!
			byte[] result = md5.digest();
			int stillNeed = key.length - currentPos;
			// Digest gave us more than we need.  Let's truncate it.
			if ( result.length > stillNeed )
			{
				byte[] b = new byte[stillNeed];
				System.arraycopy( result, 0, b, 0, b.length );
				result = b;
			}
			System.arraycopy( result, 0, key, currentPos, result.length );
			currentPos += result.length;
			if ( currentPos < key.length )
			{
				// Next round starts with a hash of the hash.
				md5.reset();
				md5.update( result );
			}
		}
		return key;
	}


	public static void main( String[] args ) throws Exception
	{
		FileInputStream fin = new FileInputStream( args[ 0 ] );
		byte[] bytes = Util.streamToBytes( fin );
		build( bytes, "changeit".toCharArray() );
	}


}
