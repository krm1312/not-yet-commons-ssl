package org.apache.commons.ssl;

import org.apache.commons.asn1.*;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

/**
 * Utility for decrypting PKCS8 private keys.  Way easier to use than
 * javax.crypto.EncryptedPrivateKeyInfo since all you need is the byte[] array
 * and the password.  You don't need to know anything else about the PKCS8
 * key you pass in.
 *
 * Can handle base64 PEM, or raw DER.
 * Can handle PKCS8 Version 1.5 and 2.0.
 * Can also handle OpenSSL encrypted or unencrypted private keys (DSA or RSA). 
 *
 * @author Julius Davies
 * @since 7-Nov-2006
 */
public class PKCS8Key
{
	private static boolean DEBUG = false;

	public final static BigInteger BIGGEST =
			new BigInteger( Integer.toString( Integer.MAX_VALUE ) );

	public final static String RSA_OID = "1.2.840.113549.1.1.1";
	public final static String DSA_OID = "1.2.840.10040.4.1";

	public final static String PKCS8_UNENCRYPTED = "PRIVATE KEY";
	public final static String PKCS8_ENCRYPTED = "ENCRYPTED PRIVATE KEY";
	public final static String OPENSSL_RSA = "RSA PRIVATE KEY";
	public final static String OPENSSL_DSA = "DSA PRIVATE KEY";

	private final PrivateKey privateKey;	
	private final byte[] decryptedBytes;
	private final String transformation;
	private final int keySize;
	private final boolean isDSA;
	private final boolean isRSA;

	static
	{
		JavaImpl.load();
	}

	/**
	 *
	 * @param in  pkcs8 file to parse (pem or der, encrypted or unencrypted)
	 *
	 * @param password  password to decrypt the pkcs8 file.  Ignored if the
	 *                  supplied pkcs8 is already unencrypted.
	 *
	 * @throws GeneralSecurityException  If a parsing or decryption problem
	 *                                   occured.
	 *
	 * @throws IOException  If the supplied InputStream could not be read.
	 */
	PKCS8Key( final InputStream in, char[] password )
			throws GeneralSecurityException, IOException
	{
	   this( Util.streamToBytes( in ), password );
	}

	/**
	 *
	 * @param in  pkcs8 file to parse (pem or der, encrypted or unencrypted)
	 *
	 * @param password  password to decrypt the pkcs8 file.  Ignored if the
	 *                  supplied pkcs8 is already unencrypted.
	 *
	 * @throws GeneralSecurityException  If a parsing or decryption problem
	 *                                   occured.
	 */
	PKCS8Key( final ByteArrayInputStream in, char[] password )
			throws GeneralSecurityException
	{
	   this( Util.streamToBytes( in ), password );	
	}

	/**
	 *
	 * @param encoded  pkcs8 file to parse (pem or der, encrypted or unencrypted)
	 *
	 * @param password  password to decrypt the pkcs8 file.  Ignored if the
	 *                  supplied pkcs8 is already unencrypted.
	 *
	 * @throws GeneralSecurityException  If a parsing or decryption problem
	 *                                   occured.
	 */		
	PKCS8Key( final byte[] encoded, char[] password )
			throws GeneralSecurityException
	{
		DecryptResult decryptResult =
				new DecryptResult( "UNENCRYPTED", 0, encoded );

		List pemItems = PEMUtil.decode( encoded );
		PEMItem keyItem = null;
		byte[] derBytes = null;
		if ( pemItems.isEmpty() )
		{
			// must be DER encoded - PEMUtil wasn't able to extract anything.
			derBytes = encoded;
		}
		else
		{
			Iterator it = pemItems.iterator();
			boolean opensslRSA = false;
			boolean opensslDSA = false;
			while ( it.hasNext() )
			{
				PEMItem item = (PEMItem) it.next();
				String type = item.pemType.trim().toUpperCase();
				boolean plainPKCS8 = type.startsWith( PKCS8_UNENCRYPTED );
				boolean encryptedPKCS8 = type.startsWith( PKCS8_ENCRYPTED );
				opensslRSA = type.startsWith( OPENSSL_RSA );
				opensslDSA = type.startsWith( OPENSSL_DSA );
				if ( plainPKCS8 || encryptedPKCS8 || opensslDSA || opensslRSA )
				{
					if ( derBytes != null )
					{
						throw new RuntimeException( "more than one pkcs8 key found in supplied byte array!" );
					}
					derBytes = item.getDerBytes();
					keyItem = item;
					decryptResult = new DecryptResult( "UNENCRYPTED", 0, derBytes );
				}
			}
			// after the loop is finished, did we find anything?
			if ( derBytes == null )
			{
				throw new RuntimeException( "no pkcs8 key found in supplied byte array!" );
			}

			if ( opensslDSA || opensslRSA )
			{
				String c = keyItem.cipher.trim();
				boolean encrypted = !"UNKNOWN".equals( c ) && !"".equals( c );
				if ( encrypted )
				{
					decryptResult = opensslDecrypt( keyItem, password );
				}

				String oid = RSA_OID;
				if ( opensslDSA )
				{
					oid = DSA_OID;
				}
				derBytes = formatAsPKCS8( decryptResult.bytes, oid, null );

				String tf = decryptResult.transformation;
				int ks = decryptResult.keySize;
				decryptResult = new DecryptResult( tf, ks, derBytes );
			}
		}

		ASN1InputStream asn = new ASN1InputStream( derBytes );
		DERSequence seq;
		try
		{
			seq = (DERSequence) asn.readObject();
		}
		catch ( IOException ioe )
		{
			ioe.printStackTrace();
			throw new RuntimeException( "asn1 parse failure: " + ioe );
		}

		PKCS8Asn1Structure pkcs8 = new PKCS8Asn1Structure();
		analyzeASN1( seq, pkcs8, 0 );

		String oid = RSA_OID;
		// With the OpenSSL unencrypted private keys in DER format, the only way
		// to even have a hope of guessing what we've got (DSA or RSA?) is to
		// count the number of DERIntegers occurring in the first DERSequence.
		int derIntegerCount = -1;
		if ( pkcs8.derIntegers != null )
		{
			derIntegerCount = pkcs8.derIntegers.size();
		}
		switch ( derIntegerCount )
		{
			case 6:
				oid = DSA_OID;
			case 9:
				derBytes = formatAsPKCS8( derBytes, oid, pkcs8 );
				pkcs8.oid1 = oid;

				String tf = decryptResult.transformation;
				int ks = decryptResult.keySize;
				decryptResult = new DecryptResult( tf, ks, derBytes );
				break;
			default:
				break;
		}

		oid = pkcs8.oid1;
		boolean isRSA = RSA_OID.equals( oid );
		boolean isDSA = DSA_OID.equals( oid );
		boolean encrypted = !isRSA && !isDSA;
		byte[] decryptedPKCS8 = encrypted ? null : derBytes;

		if ( encrypted )
		{
			decryptResult = decryptPKCS8( pkcs8, password );
			decryptedPKCS8 = decryptResult.bytes;
		}
		if ( encrypted )
		{
			asn = new ASN1InputStream( decryptedPKCS8 );
			try
			{
				seq = (DERSequence) asn.readObject();
			}
			catch ( IOException ioe )
			{
				ioe.printStackTrace();
				throw new RuntimeException( "asn1 parse failure: " + ioe );
			}
			pkcs8 = new PKCS8Asn1Structure();
			analyzeASN1( seq, pkcs8, 0 );
			oid = pkcs8.oid1;
			isDSA = DSA_OID.equals( oid );
		}

		KeySpec spec = new PKCS8EncodedKeySpec( decryptedPKCS8 );
		PrivateKey pk = null;
		try
		{
			KeyFactory KF;
			if ( isDSA )
			{
				KF = KeyFactory.getInstance( "DSA" );
			}
			else
			{
				KF = KeyFactory.getInstance( "RSA" );
			}
			pk = KF.generatePrivate( spec );
		}
		catch ( Exception e )
		{
			e.printStackTrace( System.out );
		}
		if ( pk != null )
		{
			this.privateKey = pk;
			this.isDSA = isDSA;
			this.isRSA = !isDSA;
			this.decryptedBytes = decryptedPKCS8;
			this.transformation = decryptResult.transformation;
			this.keySize = decryptResult.keySize;
		}
		else
		{
			throw new GeneralSecurityException( "failed to decrypt/parse PKCS8 bytes" );
		}
	}

	public boolean isRSA()
	{
		return isRSA;
	}

	public boolean isDSA()
	{
		return isDSA;
	}

	public String getTransformation()
	{
		return transformation;
	}

	public int getKeySize()
	{
		return keySize;
	}

	public byte[] getDecryptedBytes()
	{
		return decryptedBytes;
	}

	public PrivateKey getPrivateKey()
	{
		return privateKey;
	}

	private static class DecryptResult
	{
		public final String transformation;
		public final int keySize;
		public final byte[] bytes;

		protected DecryptResult( String transformation, int keySize,
		                         byte[] decryptedBytes )
		{
			this.transformation = transformation;
			this.keySize = keySize;
			this.bytes = decryptedBytes;
		}
	}	

	private static DecryptResult opensslDecrypt( PEMItem item, char[] password )
			throws GeneralSecurityException
	{
		String cipher = item.cipher;
		String mode = item.mode;
		int keySize = item.keySizeInBits;
		byte[] salt = item.iv;
		byte[] pwd = new byte[password.length];
		for ( int i = 0; i < password.length; i++ )
		{
			pwd[ i ] = (byte) password[ i ];
		}
		MessageDigest md = MessageDigest.getInstance( "MD5" );
		DerivedKey dk = deriveKeyOpenSSL( pwd, salt, keySize, md );
		return decrypt( cipher, mode, dk, item.des2, null, item.getDerBytes() );
	}

	public static DecryptResult decrypt( String cipher, String mode,
	                                     final DerivedKey dk,
	                                     final boolean des2,
	                                     final byte[] iv,
	                                     final byte[] encryptedBytes )

			throws NoSuchAlgorithmException, NoSuchPaddingException,
			       InvalidKeyException, InvalidAlgorithmParameterException
	{
		if ( des2 && dk.key.length >= 24 )
		{
			// copy first 8 bytes into last 8 bytes to create 2DES key.
			System.arraycopy( dk.key, 0, dk.key, 16, 8 );
		}

		int keySize = dk.key.length * 8;
		cipher = cipher.trim();
		mode = mode.trim().toUpperCase();
		// Is the cipher even available?
		Cipher.getInstance( cipher );
		String padding = "PKCS5Padding";
		if ( "CFB".equals( mode ) || "OFB".equals( mode ) )
		{
			padding = "NoPadding";
		}

		String transformation = cipher + "/" + mode + "/" + padding;
		if ( "RC4".equals( cipher ) )
		{
			// RC4 does not take mode or padding.
			transformation = cipher;
		}

		SecretKey secret = new SecretKeySpec( dk.key, cipher );
		IvParameterSpec ivParams;
		if ( iv != null )
		{
			ivParams = new IvParameterSpec( iv );
		}
		else
		{
			ivParams = dk.iv != null ? new IvParameterSpec( dk.iv ) : null;
		}
		InputStream in = new ByteArrayInputStream( encryptedBytes );
		try
		{
			Cipher c = Cipher.getInstance( transformation );

			// RC2 requires special params to inform engine of keysize.
			if ( "RC2".equalsIgnoreCase( cipher ) )
			{
				RC2ParameterSpec rcParams;
				if ( "ECB".equals( mode ) || ivParams == null )
				{
					// ECB doesn't take an IV.
					rcParams = new RC2ParameterSpec( keySize );
				}
				else
				{
					rcParams = new RC2ParameterSpec( keySize, ivParams.getIV() );
				}
				c.init( Cipher.DECRYPT_MODE, secret, rcParams );
			}
			else if ( "ECB".equals( mode ) || "RC4".equals( cipher ) )
			{
				// RC4 doesn't require any params.
				// Any cipher using ECB does not require an IV. 
				c.init( Cipher.DECRYPT_MODE, secret );
			}
			else
			{
				// DES, DESede, AES, BlowFish require IVParams (when in CBC, CFB,
				// or OFB mode).  (In ECB mode they don't require IVParams).
				c.init( Cipher.DECRYPT_MODE, secret, ivParams );
			}
			in = new CipherInputStream( in, c );

			byte[] decryptedBytes = Util.streamToBytes( in );
			return new DecryptResult( transformation, keySize, decryptedBytes );
		}
		catch ( IOException e )
		{
			// unlikely to happen, since we're backed by a ByteArrayInputStream
			e.printStackTrace();
			throw new RuntimeException( "couldn't read CipherInputStream: " + e.toString() );
		}
	}

	private static DecryptResult decryptPKCS8( PKCS8Asn1Structure pkcs8,
	                                           char[] password )
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			       InvalidKeyException, InvalidAlgorithmParameterException
	{

		if ( DEBUG )
		{
			System.out.println( "Trying to decrypt: " + pkcs8 );
		}

		boolean isVersion1 = true;
		boolean isVersion2 = false;
		boolean usePKCS12PasswordPadding = false;
		boolean use2DES = false;
		String cipher = null;
		String hash = null;
		int keySize = -1;
		// Almost all PKCS8 encrypted keys use CBC.  Looks like the AES OID's can
		// support different modes, and RC4 doesn't use any mode at all!
		String mode = "CBC";

		// In PKCS8 Version 2 the IV is stored in the ASN.1 structure for
		// us, so we don't need to derive it.  Just leave "ivSize" set to 0 for
		// those ones.
		int ivSize = 0;

		String oid = pkcs8.oid1;
		if ( oid.startsWith( "1.2.840.113549.1.12." ) )  // PKCS12 key derivation!
		{
			usePKCS12PasswordPadding = true;

			// Let's trim this OID to make life a little easier.
			oid = oid.substring( "1.2.840.113549.1.12.".length() );

			if ( oid.equals( "1.1" ) || oid.startsWith( "1.1." ) )
			{
				// 1.2.840.113549.1.12.1.1
				hash = "SHA1";
				cipher = "RC4";
				keySize = 128;
			}
			else if ( oid.equals( "1.2" ) || oid.startsWith( "1.2." ) )
			{
				// 1.2.840.113549.1.12.1.2
				hash = "SHA1";
				cipher = "RC4";
				keySize = 40;
			}
			else if ( oid.equals( "1.3" ) || oid.startsWith( "1.3." ) )
			{
				// 1.2.840.113549.1.12.1.3
				hash = "SHA1";
				cipher = "DESede";
				keySize = 192;
			}
			else if ( oid.equals( "1.4" ) || oid.startsWith( "1.4." ) )
			{
				// DES2 !!!

				// 1.2.840.113549.1.12.1.4
				hash = "SHA1";
				cipher = "DESede";
				keySize = 192;
				use2DES = true;
				// later on we'll copy the first 8 bytes of the 24 byte DESede key
				// over top the last 8 bytes, making the key look like K1-K2-K1
				// instead of the usual K1-K2-K3.
			}
			else if ( oid.equals( "1.5" ) || oid.startsWith( "1.5." ) )
			{
				// 1.2.840.113549.1.12.1.5
				hash = "SHA1";
				cipher = "RC2";
				keySize = 128;
			}
			else if ( oid.equals( "1.6" ) || oid.startsWith( "1.6." ) )
			{
				// 1.2.840.113549.1.12.1.6
				hash = "SHA1";
				cipher = "RC2";
				keySize = 40;
			}
		}
		else if ( oid.startsWith( "1.2.840.113549.1.5." ) )
		{
			// Let's trim this OID to make life a little easier.
			oid = oid.substring( "1.2.840.113549.1.5.".length() );

			if ( oid.equals( "1" ) || oid.startsWith( "1." ) )
			{
				// 1.2.840.113549.1.5.1 -- pbeWithMD2AndDES-CBC
				hash = "MD2";
				cipher = "DES";
				keySize = 64;
			}
			else if ( oid.equals( "3" ) || oid.startsWith( "3." ) )
			{
				// 1.2.840.113549.1.5.3 -- pbeWithMD5AndDES-CBC
				hash = "MD5";
				cipher = "DES";
				keySize = 64;
			}
			else if ( oid.equals( "4" ) || oid.startsWith( "4." ) )
			{
				// 1.2.840.113549.1.5.4 -- pbeWithMD2AndRC2_CBC
				hash = "MD2";
				cipher = "RC2";
				keySize = 64;
			}
			else if ( oid.equals( "6" ) || oid.startsWith( "6." ) )
			{
				// 1.2.840.113549.1.5.6 -- pbeWithMD5AndRC2_CBC
				hash = "MD5";
				cipher = "RC2";
				keySize = 64;
			}
			else if ( oid.equals( "10" ) || oid.startsWith( "10." ) )
			{
				// 1.2.840.113549.1.5.10 -- pbeWithSHA1AndDES-CBC
				hash = "SHA1";
				cipher = "DES";
				keySize = 64;
			}
			else if ( oid.equals( "11" ) || oid.startsWith( "11." ) )
			{
				// 1.2.840.113549.1.5.11 -- pbeWithSHA1AndRC2_CBC
				hash = "SHA1";
				cipher = "RC2";
				keySize = 64;
			}
			else if ( oid.equals( "12" ) || oid.startsWith( "12." ) )
			{
				// 1.2.840.113549.1.5.12 - id-PBKDF2 - Key Derivation Function
				isVersion2 = true;
			}
			else if ( oid.equals( "13" ) || oid.startsWith( "13." ) )
			{
				// 1.2.840.113549.1.5.13 - id-PBES2: PBES2 encryption scheme
				isVersion2 = true;
			}
			else if ( oid.equals( "14" ) || oid.startsWith( "14." ) )
			{
				// 1.2.840.113549.1.5.14 - id-PBMAC1 message authentication scheme
				isVersion2 = true;
			}
		}
		if ( isVersion2 )
		{
			isVersion1 = false;
			hash = "HmacSHA1";
			oid = pkcs8.oid2;

			// really ought to be:
			//
			// if ( oid.startsWith( "1.2.840.113549.1.5.12" ) )
			//
			// but all my tests still pass, and I figure this to be more robust:
			if ( pkcs8.oid3 != null )
			{
				oid = pkcs8.oid3;
			}
			if ( oid.startsWith( "1.3.6.1.4.1.3029.1.2" ) )
			{
				// 1.3.6.1.4.1.3029.1.2 - Blowfish
				cipher = "Blowfish";
				mode = "CBC";
				keySize = 128;
			}
			else if ( oid.startsWith( "1.3.14.3.2." ) )
			{
				oid = oid.substring( "1.3.14.3.2.".length() );
				if ( oid.equals( "6" ) || oid.startsWith( "6." ) )
				{
					// 1.3.14.3.2.6 - desECB
					cipher = "DES";
					mode = "ECB";
					keySize = 64;
				}
				else if ( oid.equals( "7" ) || oid.startsWith( "7." ) )
				{
					// 1.3.14.3.2.7 - desCBC
					cipher = "DES";
					mode = "CBC";
					keySize = 64;
				}
				else if ( oid.equals( "8" ) || oid.startsWith( "8." ) )
				{
					// 1.3.14.3.2.8 - desOFB
					cipher = "DES";
					mode = "OFB";
					keySize = 64;
				}
				else if ( oid.equals( "9" ) || oid.startsWith( "9." ) )
				{
					// 1.3.14.3.2.9 - desCFB
					cipher = "DES";
					mode = "CFB";
					keySize = 64;
				}
				else if ( oid.equals( "17" ) || oid.startsWith( "17." ) )
				{
					// 1.3.14.3.2.17 - desEDE
					cipher = "DESede";
					mode = "CBC";
					keySize = 192;

					// If the supplied IV is all zeroes, then this is DES2
					// (Well, that's what happened when I played with OpenSSL!)
					if ( allZeroes( pkcs8.iv ) )
					{
						mode = "ECB";
						use2DES = true;
						pkcs8.iv = null;
					}
				}
			}

			// AES
			// 2.16.840.1.101.3.4.1.1  - id-aes128-ECB
			// 2.16.840.1.101.3.4.1.2  - id-aes128-CBC
			// 2.16.840.1.101.3.4.1.3  - id-aes128-OFB
			// 2.16.840.1.101.3.4.1.4  - id-aes128-CFB
			// 2.16.840.1.101.3.4.1.21 - id-aes192-ECB
			// 2.16.840.1.101.3.4.1.22 - id-aes192-CBC
			// 2.16.840.1.101.3.4.1.23 - id-aes192-OFB
			// 2.16.840.1.101.3.4.1.24 - id-aes192-CFB
			// 2.16.840.1.101.3.4.1.41 - id-aes256-ECB
			// 2.16.840.1.101.3.4.1.42 - id-aes256-CBC
			// 2.16.840.1.101.3.4.1.43 - id-aes256-OFB
			// 2.16.840.1.101.3.4.1.44 - id-aes256-CFB
			else if ( oid.startsWith( "2.16.840.1.101.3.4.1." ) )
			{
				cipher = "AES";
				if ( pkcs8.iv == null )
				{
					ivSize = 128;
				}
				oid = oid.substring( "2.16.840.1.101.3.4.1.".length() );
				int x = oid.indexOf( '.' );
				int finalDigit;
				if ( x >= 0 )
				{
					finalDigit = Integer.parseInt( oid.substring( 0, x ) );
				}
				else
				{
					finalDigit = Integer.parseInt( oid );
				}
				switch ( finalDigit % 10 )
				{
					case 1:
						mode = "ECB";
						break;
					case 2:
						mode = "CBC";
						break;
					case 3:
						mode = "OFB";
						break;
					case 4:
						mode = "CFB";
						break;
					default:
						throw new RuntimeException( "Unknown AES final digit: " + finalDigit );
				}
				switch ( finalDigit / 10 )
				{
					case 0:
						keySize = 128;
						break;
					case 2:
						keySize = 192;
						break;
					case 4:
						keySize = 256;
						break;
					default:
						throw new RuntimeException( "Unknown AES final digit: " + finalDigit );
				}
			}
			else if ( oid.startsWith( "1.2.840.113549.3." ) )
			{
				// Let's trim this OID to make life a little easier.
				oid = oid.substring( "1.2.840.113549.3.".length() );

				if ( oid.equals( "2" ) || oid.startsWith( "2." ) )
				{
					// 1.2.840.113549.3.2 - RC2-CBC
					// Note:  keysize determined in PKCS8 Version 2.0 ASN.1 field.
					cipher = "RC2";
					keySize = pkcs8.keySize * 8;
				}
				else if ( oid.equals( "4" ) || oid.startsWith( "4." ) )
				{
					// 1.2.840.113549.3.4 - RC4
					// Note:  keysize determined in PKCS8 Version 2.0 ASN.1 field.
					cipher = "RC4";
					keySize = pkcs8.keySize * 8;
				}
				else if ( oid.equals( "7" ) || oid.startsWith( "7." ) )
				{
					// 1.2.840.113549.3.7 - DES-EDE3-CBC
					cipher = "DESede";
					keySize = 192;
				}
				else if ( oid.equals( "9" ) || oid.startsWith( "9." ) )
				{
					// 1.2.840.113549.3.9 - RC5 CBC Pad
					// Note:  keysize determined in PKCS8 Version 2.0 ASN.1 field.
					keySize = pkcs8.keySize * 8;
					cipher = "RC5";

					// Need to find out more about RC5.
					// How do I create the RC5ParameterSpec?
					// (int version, int rounds, int wordSize, byte[] iv)
				}
			}
		}

		// In PKCS8 Version 1.5 we need to derive an 8 byte IV.  In those cases
		// the ASN.1 structure doesn't have the IV, anyway, so I can use that
		// to decide whether to derive one or not.
		//
		// Note:  if AES, then IV has to be 16 bytes.
		if ( pkcs8.iv == null )
		{
			ivSize = 64;
		}

		byte[] salt = pkcs8.salt;
		int ic = pkcs8.iterationCount;

		// PKCS8 converts the password to a byte[] array using a simple
		// cast.  This byte[] array is ignored if we're using the PKCS12
		// key derivation, since that employs a different technique.
		byte[] pwd = new byte[password.length];
		for ( int i = 0; i < pwd.length; i++ )
		{
			pwd[ i ] = (byte) password[ i ];
		}

		DerivedKey dk;
		if ( usePKCS12PasswordPadding )
		{
			MessageDigest md = MessageDigest.getInstance( hash );
			dk = deriveKeyPKCS12( password, salt, ic, keySize, ivSize, md );
		}
		else
		{
			if ( isVersion1 )
			{
				MessageDigest md = MessageDigest.getInstance( hash );
				dk = deriveKeyV1( pwd, salt, ic, keySize, ivSize, md );
			}
			else
			{
				Mac mac = Mac.getInstance( hash );
				dk = deriveKeyV2( pwd, salt, ic, keySize, ivSize, mac );
			}
		}


		return decrypt( cipher, mode, dk, use2DES, pkcs8.iv, pkcs8.bigPayload );
	}

	public static DerivedKey deriveKeyOpenSSL( byte[] password, byte[] salt,
	                                           int keySizeInBits,
	                                           MessageDigest md )
	{
		md.reset();
		byte[] key = new byte[keySizeInBits / 8];
		if ( salt == null || salt.length == 0 )
		{
			// RC4 problem - OpenSSL isn't giving us the salt!
			salt = null;
		}
		byte[] result;
		int currentPos = 0;
		while ( currentPos < key.length )
		{
			md.update( password );
			// salt is only null for RC4
			if ( salt != null )
			{
				// First 8 bytes of salt ONLY!  (That wasn't obvious to me with
				// those longer AES salts.   MUCH gnashing of teeth.)
				md.update( salt, 0, 8 );
			}
			result = md.digest();
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
				md.reset();
				md.update( result );
			}
		}
		return new DerivedKey( key, salt );
	}

	public static DerivedKey deriveKeyV1( byte[] password, byte[] salt,
	                                      int iterations, int keySizeInBits,
	                                      int ivSizeInBits, MessageDigest md )
	{
		int keySize = keySizeInBits / 8;
		int ivSize = ivSizeInBits / 8;
		md.reset();
		md.update( password );
		byte[] result = md.digest( salt );
		for ( int i = 1; i < iterations; i++ )
		{
			// Hash of the hash for each of the iterations.
			result = md.digest( result );
		}
		byte[] key = new byte[keySize];
		byte[] iv = new byte[ivSize];
		System.arraycopy( result, 0, key, 0, key.length );
		System.arraycopy( result, key.length, iv, 0, iv.length );
		return new DerivedKey( key, iv );
	}

	public static DerivedKey deriveKeyPKCS12( char[] password, byte[] salt,
	                                          int iterations, int keySizeInBits,
	                                          int ivSizeInBits,
	                                          MessageDigest md )
	{
		byte[] pwd;
		if ( password.length > 0 )
		{
			pwd = new byte[( password.length + 1 ) * 2];
			for ( int i = 0; i < password.length; i++ )
			{
				pwd[ i * 2 ] = (byte) ( password[ i ] >>> 8 );
				pwd[ i * 2 + 1 ] = (byte) password[ i ];
			}
		}
		else
		{
			pwd = new byte[0];
		}
		int keySize = keySizeInBits / 8;
		int ivSize = ivSizeInBits / 8;
		byte[] key = pkcs12( 1, keySize, salt, pwd, iterations, md );
		byte[] iv = pkcs12( 2, ivSize, salt, pwd, iterations, md );
		return new DerivedKey( key, iv );
	}

	private static byte[] pkcs12( int idByte, int n, byte[] salt,
	                              byte[] password, int iterationCount,
	                              MessageDigest md )
	{
		int u = md.getDigestLength();
		// sha1, md2, md5 all use 512 bits.  But future hashes might not.
		int v = 512 / 8;
		md.reset();
		byte[] D = new byte[v];
		byte[] dKey = new byte[n];
		for ( int i = 0; i != D.length; i++ )
		{
			D[ i ] = (byte) idByte;
		}
		byte[] S;
		if ( ( salt != null ) && ( salt.length != 0 ) )
		{
			S = new byte[v * ( ( salt.length + v - 1 ) / v )];
			for ( int i = 0; i != S.length; i++ )
			{
				S[ i ] = salt[ i % salt.length ];
			}
		}
		else
		{
			S = new byte[0];
		}
		byte[] P;
		if ( ( password != null ) && ( password.length != 0 ) )
		{
			P = new byte[v * ( ( password.length + v - 1 ) / v )];
			for ( int i = 0; i != P.length; i++ )
			{
				P[ i ] = password[ i % password.length ];
			}
		}
		else
		{
			P = new byte[0];
		}
		byte[] I = new byte[S.length + P.length];
		System.arraycopy( S, 0, I, 0, S.length );
		System.arraycopy( P, 0, I, S.length, P.length );
		byte[] B = new byte[v];
		int c = ( n + u - 1 ) / u;
		for ( int i = 1; i <= c; i++ )
		{
			md.update( D );
			byte[] result = md.digest( I );
			for ( int j = 1; j != iterationCount; j++ )
			{
				result = md.digest( result );
			}
			for ( int j = 0; j != B.length; j++ )
			{
				B[ j ] = result[ j % result.length ];
			}
			for ( int j = 0; j < ( I.length / v ); j++ )
			{
				/*
				 * add a + b + 1, returning the result in a. The a value is treated
				 * as a BigInteger of length (b.length * 8) bits. The result is
				 * modulo 2^b.length in case of overflow.
				 */
				int aOff = j * v;
				int bLast = B.length - 1;
				int x = ( B[ bLast ] & 0xff ) + ( I[ aOff + bLast ] & 0xff ) + 1;
				I[ aOff + bLast ] = (byte) x;
				x >>>= 8;
				for ( int k = B.length - 2; k >= 0; k-- )
				{
					x += ( B[ k ] & 0xff ) + ( I[ aOff + k ] & 0xff );
					I[ aOff + k ] = (byte) x;
					x >>>= 8;
				}
			}
			if ( i == c )
			{
				System.arraycopy( result, 0, dKey, ( i - 1 ) * u, dKey.length - ( ( i - 1 ) * u ) );
			}
			else
			{
				System.arraycopy( result, 0, dKey, ( i - 1 ) * u, result.length );
			}
		}
		return dKey;
	}

	public static DerivedKey deriveKeyV2( byte[] password, byte[] salt,
	                                      int iterations, int keySizeInBits,
	                                      int ivSizeInBits, Mac mac )
			throws InvalidKeyException
	{
		int keySize = keySizeInBits / 8;
		int ivSize = ivSizeInBits / 8;

		// Because we're using an Hmac, we need to initialize with a SecretKey.
		// HmacSHA1 doesn't need SecretKeySpec's 2nd parameter, hence the "N/A".  
		SecretKeySpec sk = new SecretKeySpec( password, "N/A" );
		mac.init( sk );
		int macLength = mac.getMacLength();
		int derivedKeyLength = keySize + ivSize;
		int blocks = ( derivedKeyLength + macLength - 1 ) / macLength;
		byte[] blockIndex = new byte[4];
		byte[] finalResult = new byte[blocks * macLength];
		for ( int i = 1; i <= blocks; i++ )
		{
			int offset = ( i - 1 ) * macLength;
			blockIndex[ 0 ] = (byte) ( i >>> 24 );
			blockIndex[ 1 ] = (byte) ( i >>> 16 );
			blockIndex[ 2 ] = (byte) ( i >>> 8 );
			blockIndex[ 3 ] = (byte) i;
			mac.reset();
			mac.update( salt );
			byte[] result = mac.doFinal( blockIndex );
			System.arraycopy( result, 0, finalResult, offset, result.length );
			for ( int j = 1; j < iterations; j++ )
			{
				mac.reset();
				result = mac.doFinal( result );
				for ( int k = 0; k < result.length; k++ )
				{
					finalResult[ offset + k ] ^= result[ k ];
				}
			}
		}
		byte[] key = new byte[keySize];
		byte[] iv = new byte[ivSize];
		System.arraycopy( finalResult, 0, key, 0, key.length );
		System.arraycopy( finalResult, key.length, iv, 0, iv.length );
		return new DerivedKey( key, iv );
	}

	private static void analyzeASN1( DEREncodable seq, PKCS8Asn1Structure pkcs8,
	                                 int depth )
	{
		if ( depth >= 2 )
		{
			pkcs8.derIntegers = null;
		}
		Enumeration en = null;
		if ( seq instanceof DERSequence )
		{
			en = ( (DERSequence) seq ).getObjects();
		}
		else if ( seq instanceof DERSet )
		{
			en = ( (DERSet) seq ).getObjects();
		}
		else
		{
			System.out.println( "BAD BAD BAD analyzeASN1 error" );
		}
		while ( en != null && en.hasMoreElements() )
		{
			DEREncodable obj = (DEREncodable) en.nextElement();
			if ( !( obj instanceof DERSequence ) && !( obj instanceof DERSet ) )
			{
				String str = obj.toString();
				String name = obj.getClass().getName();
				name = name.substring( name.lastIndexOf( '.' ) + 1 );
				for ( int i = 0; i < depth; i++ )
				{
					name = "  " + name;
				}
				if ( obj instanceof DERInteger )
				{
					DERInteger dInt = (DERInteger) obj;
					if ( pkcs8.derIntegers != null )
					{
						pkcs8.derIntegers.add( dInt );
					}
					BigInteger big = dInt.toBigInteger();
					int intValue = big.intValue();
					if ( BIGGEST.compareTo( big ) >= 0 && intValue > 0 )
					{
						if ( pkcs8.iterationCount == 0 )
						{
							pkcs8.iterationCount = intValue;
						}
						else if ( pkcs8.keySize == 0 )
						{
							pkcs8.keySize = intValue;
						}
					}
					str = dInt.toBigInteger().toString();
				}
				else if ( obj instanceof DERObjectIdentifier )
				{
					DERObjectIdentifier id = (DERObjectIdentifier) obj;
					str = id.getIdentifier();
					if ( pkcs8.oid1 == null )
					{
						pkcs8.oid1 = str;
					}
					else if ( pkcs8.oid2 == null )
					{
						pkcs8.oid2 = str;
					}
					else if ( pkcs8.oid3 == null )
					{
						pkcs8.oid3 = str;
					}
				}
				else
				{
					pkcs8.derIntegers = null;
					if ( obj instanceof DERTaggedObject )
					{
						DERTaggedObject tag = (DERTaggedObject) obj;
						str = tag.getTagNo() + ": " + tag.getObject();
					}
					if ( obj instanceof DEROctetString )
					{
						DEROctetString oct = (DEROctetString) obj;
						byte[] octets = oct.getOctets();
						int len = Math.min( 10, octets.length );
						boolean probablyBinary = false;
						for ( int i = 0; i < len; i++ )
						{
							byte b = octets[ i ];
							boolean isBinary = b > 128 || b < 0;
							if ( isBinary )
							{
								probablyBinary = true;
								break;
							}
						}
						if ( probablyBinary && octets.length > 64 )
						{
							if ( pkcs8.bigPayload == null )
							{
								pkcs8.bigPayload = octets;
							}
							str = "probably binary";
						}
						else
						{
							str = PEMUtil.bytesToHex( octets );
							if ( octets.length <= 64 )
							{
								if ( octets.length % 8 == 0 )
								{
									if ( pkcs8.salt == null )
									{
										pkcs8.salt = octets;
									}
									else if ( pkcs8.iv == null )
									{
										pkcs8.iv = octets;
									}
								}
								else
								{
									if ( pkcs8.smallPayload == null )
									{
										pkcs8.smallPayload = octets;
									}
								}
							}
						}
						str += " (length=" + octets.length + ")";
					}
					else if ( obj instanceof DERPrintableString )
					{
						DERPrintableString dps = (DERPrintableString) obj;
						str = dps.getString();
					}
				}

				if ( DEBUG )
				{
					System.out.println( name + ": [" + str + "]" );
				}
			}
			else
			{
				analyzeASN1( obj, pkcs8, depth + 1 );
			}
		}
	}


	private static class PKCS8Asn1Structure
	{
		protected List derIntegers = new LinkedList();
		protected String oid1;
		protected String oid2;
		protected String oid3;
		protected byte[] salt;
		protected byte[] iv;
		protected int iterationCount;
		protected int keySize;
		protected byte[] bigPayload;
		protected byte[] smallPayload;

		public String toString()
		{
			StringBuffer buf = new StringBuffer( 256 );
			buf.append( "---------- pkcs8 ------------" );
			buf.append( "\noid1:    " );
			buf.append( oid1 );
			if ( oid2 != null )
			{
				buf.append( "\noid2:    " );
				buf.append( oid2 );
			}
			buf.append( "\nsalt:   " );
			if ( salt != null )
			{
				buf.append( PEMUtil.bytesToHex( salt ) );
			}
			else
			{
				buf.append( "[null]" );
			}
			buf.append( "\nic:      " );
			buf.append( Integer.toString( iterationCount ) );
			if ( keySize != 0 )
			{
				buf.append( "\nkeySize: " );
				buf.append( Integer.toString( keySize * 8 ) );
			}
			if ( oid2 != null )
			{
				buf.append( "\noid3:    " );
				buf.append( oid3 );
			}
			if ( oid2 != null )
			{
				buf.append( "\niv:      " );
				if ( iv != null )
				{
					buf.append( PEMUtil.bytesToHex( iv ) );
				}
				else
				{
					buf.append( "[null]" );
				}
			}
			return buf.toString();
		}
	}

	public static byte[] formatAsPKCS8( byte[] privateKey, String oid,
	                                    PKCS8Asn1Structure pkcs8 )
	{
		DERInteger derZero = DERInteger.valueOf( 0 );
		DERSequence outter = new DERSequence();
		DERSequence inner = new DERSequence();
		outter.add( derZero );
		outter.add( inner );
		try
		{
			DERObjectIdentifier derOID = DERObjectIdentifier.valueOf( oid );
			inner.add( derOID );
			if ( DSA_OID.equals( oid ) )
			{
				if ( pkcs8 == null )
				{
					ASN1InputStream asn = new ASN1InputStream( privateKey );
					DERSequence seq;
					try
					{
						seq = (DERSequence) asn.readObject();
					}
					catch ( IOException ioe )
					{
						ioe.printStackTrace();
						throw new RuntimeException( "asn1 parse failure " + ioe );
					}
					pkcs8 = new PKCS8Asn1Structure();
					analyzeASN1( seq, pkcs8, 0 );
				}
				if ( pkcs8.derIntegers == null || pkcs8.derIntegers.size() < 6 )
				{
					throw new RuntimeException( "invalid DSA key - can't find P, Q, G, X" );
				}

				DERInteger[] ints = new DERInteger[pkcs8.derIntegers.size()];
				pkcs8.derIntegers.toArray( ints );
				DERInteger p = ints[ 1 ];
				DERInteger q = ints[ 2 ];
				DERInteger g = ints[ 3 ];
				DERInteger x = ints[ 5 ];

				byte[] encodedX = encode( x );
				DEROctetString xAsOctets = new DEROctetString( encodedX );
				DERSequence pqg = new DERSequence();
				pqg.add( p );
				pqg.add( q );
				pqg.add( g );

				inner.add( pqg );
				outter.add( xAsOctets );
			}
			else
			{
				inner.add( DERNull.DER_NULL );
				DEROctetString octet = new DEROctetString( privateKey );
				outter.add( octet );
			}
			return encode( outter );
		}
		catch ( IOException ioe )
		{
			throw JavaImpl.newRuntimeException( ioe );
		}
	}

	private static boolean allZeroes( byte[] b )
	{
		for ( int i = 0; i < b.length; i++ )
		{
			if ( b[ i ] != 0 )
			{
				return false;
			}
		}
		return true;
	}

	public static byte[] encode( DEREncodable der ) throws IOException
	{
		ByteArrayOutputStream baos = new ByteArrayOutputStream( 1024 );
		ASN1OutputStream out = new ASN1OutputStream( baos );
		der.encode( out );
		out.close();
		return baos.toByteArray();
	}



	public static void main( String[] args ) throws Exception
	{
		byte[] original = null;
		for ( int i = 0; i < args.length; i++ )
		{
			FileInputStream in = new FileInputStream( args[ i ] );
			byte[] bytes = Util.streamToBytes( in );
			PKCS8Key key = null;
			try
			{
				key = new PKCS8Key( bytes, "changeit".toCharArray() );
			}
			catch ( Exception e )
			{
				System.out.println( " FAILED! " + args[ i ] );
				e.printStackTrace( System.out );
			}
			if ( key != null )
			{
				byte[] decrypted = key.getDecryptedBytes();
				int keySize = key.getKeySize();
				String keySizeStr = "" + keySize;
				if ( keySize < 10 )
				{
					keySizeStr = "  " + keySizeStr;
				}
				else if ( keySize < 100 )
				{
					keySizeStr = " " + keySizeStr;
				}
				StringBuffer buf = new StringBuffer( key.getTransformation() );
				int maxLen = "Blowfish/CBC/PKCS5Padding".length();
				for ( int j = buf.length(); j < maxLen; j++ )
				{
					buf.append( ' ' );
				}
				String transform = buf.toString();
				String type = key.isDSA() ? "DSA" : "RSA";

				if ( original == null )
				{
					original = decrypted;
					System.out.println( "   SUCCESS    \t" + type + "\t" + transform + "\t" + keySizeStr + "\t" + args[ i ] );
				}
				else
				{
					boolean identical = Arrays.equals( original, decrypted );
					if ( !identical )
					{
						System.out.println( "***FAILURE*** \t" + type + "\t" + transform + "\t" + keySizeStr + "\t" + args[ i ] );
					}
					else
					{
						System.out.println( "   SUCCESS    \t" + type + "\t" + transform + "\t" + keySizeStr + "\t" + args[ i ] );
					}
				}
			}
		}
	}
	
}
