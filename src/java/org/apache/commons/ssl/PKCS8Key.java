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
 * @author Julius Davies
 * @since 7-Nov-2006
 */
public class PKCS8Key
{
	private final static boolean DEBUG = false;

	public final static BigInteger BIGGEST =
			new BigInteger( Integer.toString( Integer.MAX_VALUE ) );

	public final static String RSA_OID = "1.2.840.113549.1.1.1";
	public final static String DSA_OID = "1.2.840.10040.4.1";

	public final static String PKCS8_UNENCRYPTED = "PRIVATE KEY";
	public final static String PKCS8_ENCRYPTED = "ENCRYPTED PRIVATE KEY";
	public final static String OPENSSL_RSA = "RSA PRIVATE KEY";
	public final static String OPENSSL_DSA = "DSA PRIVATE KEY";

	private final byte[] decryptedBytes;

	static
	{
		JavaImpl.load();
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
				if ( original == null )
				{
					original = decrypted;
					System.out.println( "  " + args[ i ] + " serving as ORIGINAL" );
				}
				else
				{
					boolean identical = Arrays.equals( original, decrypted );
					if ( !identical )
					{
						throw new RuntimeException( "failed on: " + args[ i ] );
					}
					else
					{
						System.out.println( "  " + args[ i ] + " PASSED!" );
					}
				}
			}
		}


	}

	PKCS8Key( final byte[] encoded, char[] password )
			throws GeneralSecurityException
	{
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
				byte[] decryptedBytes;
				if ( encrypted )
				{
					decryptedBytes = opensslDecrypt( keyItem, password );
				}
				else
				{
					decryptedBytes = derBytes;
				}

				String oid = RSA_OID;
				if ( opensslDSA )
				{
					oid = DSA_OID;
				}
				derBytes = formatAsPKCS8( decryptedBytes, oid, null );
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
			throw new RuntimeException( "asn1 parse failure", ioe );
		}

		PKCS8Asn1Structure pkcs8 = new PKCS8Asn1Structure();
		analyzeASN1( seq, pkcs8, 0 );

		String oid = RSA_OID;
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
			try
			{
				decryptedPKCS8 = decrypt( pkcs8, password );
			}
			catch ( GeneralSecurityException gse )
			{
				throw JavaImpl.newRuntimeException( gse );
			}
		}

		// System.out.println( Certificates.toString( decryptedPKCS8 ) );

		if ( encrypted )
		{
			asn = new ASN1InputStream( decryptedPKCS8 );
			try
			{
				seq = (DERSequence) asn.readObject();
			}
			catch ( IOException ioe )
			{
				throw new RuntimeException( ioe );
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
			this.decryptedBytes = decryptedPKCS8;
			// System.out.println( pk );
			// System.out.println( PEMUtil.formatRSAPrivateKey( (RSAPrivateCrtKey) pk ) );
			// System.out.println( Certificates.toString( pk.getEncoded() ) );
		}
		else
		{
			throw new GeneralSecurityException( "failed to decrypt/parse PKCS8 bytes" );
		}
	}

	public byte[] getDecryptedBytes()
	{
		return decryptedBytes;
	}

	private byte[] opensslDecrypt( PEMItem item, char[] password )
			throws GeneralSecurityException
	{
		byte[] pwd = new byte[password.length];
		for ( int i = 0; i < password.length; i++ )
		{
			pwd[ i ] = (byte) password[ i ];
		}

		String cipher = item.cipher.trim();

		// Is the cipher even available?
		Cipher.getInstance( cipher );

		String hash = "MD5";
		String mode = item.mode;
		int keySize = item.keySizeInBits;
		byte[] salt = item.iv;

		MessageDigest md;
		try
		{
			md = MessageDigest.getInstance( hash );
		}
		catch ( NoSuchAlgorithmException nsae )
		{
			throw new RuntimeException( nsae );
		}

		String transformation = cipher + "/" + mode + "/PKCS5Padding";
		System.out.print( transformation + " keysize: " + keySize );
		DerivedKey dk = deriveKeyOpenSSL( pwd, salt, keySize, md );
		SecretKey secret = new SecretKeySpec( dk.key, cipher );
		IvParameterSpec ivParams = new IvParameterSpec( dk.iv );
		InputStream in = new ByteArrayInputStream( item.getDerBytes() );
		try
		{
			Cipher c = Cipher.getInstance( transformation );
			if ( "RC2".equalsIgnoreCase( cipher ) )
			{
				RC2ParameterSpec rcParams = new RC2ParameterSpec( keySize, dk.iv );
				c.init( Cipher.DECRYPT_MODE, secret, rcParams );
			}
			else if ( "RC4".equalsIgnoreCase( cipher ) )
			{
				c.init( Cipher.DECRYPT_MODE, secret );
			}
			else
			{
				c.init( Cipher.DECRYPT_MODE, secret, ivParams );
			}
			in = new CipherInputStream( in, c );
			return Util.streamToBytes( in );
		}
		catch ( IOException e )
		{
			// unlikely to happen, since we're backed by a ByteArrayInputStream
			throw new RuntimeException( e );
		}
	}

	private byte[] decrypt( PKCS8Asn1Structure pkcs8, char[] password )
			throws NoSuchAlgorithmException, NoSuchPaddingException
	{

		if ( DEBUG )
		{
			System.out.println( "Trying to decrypt: " + pkcs8 );
		}

		boolean isVersion1 = true;
		boolean isVersion2 = false;
		boolean usePKCS12PasswordPadding = false;
		boolean use2DES = false;
		String cipher = "DES";
		String hash = "MD5";
		String mode = "CBC";
		int keySize = 64; // default for DES, might be changed below.
		int ivSize = 0;
		if ( pkcs8.salt2 == null )
		{
			ivSize = 64;
		}
		String oid = pkcs8.oid1;
		if ( oid.startsWith( "1.2.840.113549.1.12" ) )
		{
			usePKCS12PasswordPadding = true;
			oid = oid.substring( "1.2.840.113549.1.12".length() );
			hash = "SHA1";
			cipher = "DESede";
			if ( oid.startsWith( ".1.1" ) )
			{
				cipher = "RC4";
				keySize = 128;
			}
			else if ( oid.startsWith( ".1.2" ) )
			{
				cipher = "RC4";
				keySize = 40;				
			}
			else if ( oid.startsWith( ".1.4" ) )
			{
				use2DES = true;
			}
			else if ( oid.startsWith( ".1.5" ) )
			{
				cipher = "RC2";
				keySize = 128;
			}
			else if ( oid.startsWith( ".1.6" ) )
			{
				cipher = "RC2";
				keySize = 40;
			}
		}
		else if ( "1.2.840.113549.1.5.1".equals( oid ) )
		{
			hash = "MD2";
		}
		else if ( "1.2.840.113549.1.5.4".equals( oid ) )
		{
			hash = "MD2";
			cipher = "RC2";
		}
		else if ( "1.2.840.113549.1.5.6".equals( oid ) )
		{
			cipher = "RC2";
		}
		else if ( "1.2.840.113549.1.5.10".equals( oid ) )
		{
			hash = "SHA1";
		}
		else if ( "1.2.840.113549.1.5.11".equals( oid ) )
		{
			hash = "SHA1";
			cipher = "RC2";
		}
		else if ( "1.2.840.113549.1.5.13".equals( oid ) )
		{
			isVersion2 = true;
		}

		if ( isVersion2 )
		{
			oid = pkcs8.oid2;
			if ( "1.2.840.113549.1.5.12".equals( oid ) )
			{
				isVersion1 = false;
				hash = "HmacSHA1";
				oid = pkcs8.oid3;
				// AES
				if ( oid.startsWith( "2.16.840.1.101.3.4.1" ) )
				{
					cipher = "AES";
					int x = oid.lastIndexOf( '.' );
					int finalDigit = Integer.parseInt( oid.substring( x + 1 ) );
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
				else if ( "1.2.840.113549.3.2".equals( oid ) )
				{
					cipher = "RC2";
				}
				else if ( "1.2.840.113549.3.4".equals( oid ) )
				{
					cipher = "RC4";
				}
				else if ( "1.2.840.113549.3.7".equals( oid ) )
				{
					cipher = "DESede";
				}
				else if ( "1.2.840.113549.3.9".equals( oid ) )
				{
					cipher = "RC5";
				}
			}
		}

		String CIPHER = cipher.toUpperCase();
		if ( CIPHER.startsWith( "RC" ) && pkcs8.keySize != 0 )
		{
			keySize = pkcs8.keySize * 8;
		}
		else if ( cipher.startsWith( "DESede" ) )
		{
			keySize = 192;
		}

		// Is the cipher even available?
		Cipher.getInstance( cipher );

		String transformation = cipher + "/" + mode + "/PKCS5Padding";
		if ( CIPHER.startsWith( "RC4" ) )
		{
			transformation = cipher;
		}
		System.out.print( transformation + " keySize: " + keySize );

		byte[] salt = pkcs8.salt1;
		int ic = pkcs8.iterationCount;
		byte[] pwd;

		DerivedKey dk;
		if ( usePKCS12PasswordPadding )
		{
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
			MessageDigest md = MessageDigest.getInstance( hash );
			dk = deriveKeyPKCS12( pwd, salt, ic, keySize, ivSize, md );
		}
		else
		{
			pwd = new byte[password.length];
			for ( int i = 0; i < pwd.length; i++ )
			{
				pwd[ i ] = (byte) password[ i ];
			}
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

		if ( use2DES && dk.key.length >= 24 )
		{
			byte[] key = dk.key;
			// copy first 8 bytes into last 8 bytes to create 2DES key.
			System.arraycopy( dk.key, 0, dk.key, 16, 8 );
		}

		SecretKey secret = new SecretKeySpec( dk.key, cipher );
		Cipher c = Cipher.getInstance( transformation );
		IvParameterSpec ivParams;
		if ( pkcs8.salt2 != null )
		{
			ivParams = new IvParameterSpec( pkcs8.salt2 );
		}
		else
		{
			ivParams = new IvParameterSpec( dk.iv );
		}

		try
		{
			if ( CIPHER.startsWith( "RC2" ) )
			{
				byte[] iv = ivParams.getIV();
				RC2ParameterSpec rcParams = new RC2ParameterSpec( keySize, iv );
				c.init( Cipher.DECRYPT_MODE, secret, rcParams );
			}
			else if ( CIPHER.startsWith( "RC4" ) )
			{
				// rc4 doesn't take any params.
				c.init( Cipher.DECRYPT_MODE, secret );
			}
			else
			{
				c.init( Cipher.DECRYPT_MODE, secret, ivParams );
			}
			byte[] encrypted = pkcs8.bigPayload;
			ByteArrayInputStream bIn = new ByteArrayInputStream( encrypted );
			InputStream in = new CipherInputStream( bIn, c );
			return Util.streamToBytes( in );
		}
		catch ( Exception e )
		{
			throw JavaImpl.newRuntimeException( e );
		}
	}

	public static DerivedKey deriveKeyOpenSSL( byte[] password, byte[] salt,
	                                           int keySizeInBits,
	                                           MessageDigest md )
	{
		md.reset();
		byte[] key = new byte[keySizeInBits / 8];
		byte[] result;
		int currentPos = 0;
		while ( currentPos < key.length )
		{
			md.update( password );
			// salt is only null for RC4
			if ( salt != null )
			{
				// First 8 bytes of salt ONLY!  (That wasn't obvious to me with those
				// longer AES salts.   MUCH gnashing of teeth.)
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

	public static DerivedKey deriveKeyPKCS12( byte[] password, byte[] salt,
	                                          int iterations, int keySizeInBits,
	                                          int ivSizeInBits, MessageDigest md )
	{
		int keySize = keySizeInBits / 8;
		int ivSize = ivSizeInBits / 8;
		byte[] key = pkcs12( 1, keySize, salt, password, iterations, md );
		byte[] iv = pkcs12( 2, ivSize, salt, password, iterations, md );
		return new DerivedKey( key, iv );
	}

	private static byte[] pkcs12( int idByte, int n, byte[] salt,
	                              byte[] password, int iterationCount,
	                              MessageDigest md )
	{
		int u = md.getDigestLength();
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
			for ( int j = 0; j != I.length / v; j++ )
			{
				adjust( I, j * v, B );
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

	/**
	 * add a + b + 1, returning the result in a. The a value is treated
	 * as a BigInteger of length (b.length * 8) bits. The result is
	 * modulo 2^b.length in case of overflow.
	 */
	private static void adjust( byte[] a, int aOff, byte[] b )
	{
		int x = ( b[ b.length - 1 ] & 0xff ) + ( a[ aOff + b.length - 1 ] & 0xff ) + 1;

		a[ aOff + b.length - 1 ] = (byte) x;
		x >>>= 8;

		for ( int i = b.length - 2; i >= 0; i-- )
		{
			x += ( b[ i ] & 0xff ) + ( a[ aOff + i ] & 0xff );
			a[ aOff + i ] = (byte) x;
			x >>>= 8;
		}
	}

	public static DerivedKey deriveKeyV2( byte[] password, byte[] salt,
	                                      int iterations, int keySizeInBits,
	                                      int ivSizeInBits, Mac mac )
	{
		int keySize = keySizeInBits / 8;
		int ivSize = ivSizeInBits / 8;
		try
		{
			SecretKeySpec key = new SecretKeySpec( password, "N/A" );
			mac.init( key );
		}
		catch ( InvalidKeyException ike )
		{
			throw new RuntimeException( ike );
		}
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
									if ( pkcs8.salt1 == null )
									{
										pkcs8.salt1 = octets;
									}
									else if ( pkcs8.salt2 == null )
									{
										pkcs8.salt2 = octets;
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
		protected byte[] salt1;
		protected byte[] salt2;
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
			buf.append( "\nsalt1:   " );
			if ( salt1 != null )
			{
				buf.append( PEMUtil.bytesToHex( salt1 ) );
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
				buf.append( "\nsalt2:   " );
				if ( salt2 != null )
				{
					buf.append( PEMUtil.bytesToHex( salt2 ) );
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
						throw new RuntimeException( "asn1 parse failure", ioe );
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

	public static byte[] encode( DEREncodable der ) throws IOException
	{
		ByteArrayOutputStream baos = new ByteArrayOutputStream( 1024 );
		ASN1OutputStream out = new ASN1OutputStream( baos );
		der.encode( out );
		out.close();
		return baos.toByteArray();
	}


}
