package org.apache.commons.ssl;

import org.apache.commons.asn1.ASN1InputStream;
import org.apache.commons.asn1.DEREncodable;
import org.apache.commons.asn1.DERInteger;
import org.apache.commons.asn1.DERObjectIdentifier;
import org.apache.commons.asn1.DEROctetString;
import org.apache.commons.asn1.DERPrintableString;
import org.apache.commons.asn1.DERSequence;
import org.apache.commons.asn1.DERSet;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * @author Julius Davies
 * @since 7-Nov-2006
 */
public class PKCS8Key
{
	public final static BigInteger BIGGEST =
			new BigInteger( Integer.toString( Integer.MAX_VALUE ) );
	public final static Map OID_CIPHER_MAPPINGS;

	public final static String UNENCRYPTED_PEM_TYPE = "PRIVATE KEY";
	public final static String ENCRYPTED_PEM_TYPE = "ENCRYPTED PRIVATE KEY";

	static
	{
		Map m1 = new TreeMap();

		// 1.2.840.113549.1.5.3 --> pbeWithMD5AndDES-CBC
		// 1.3.14.3.2.7  --> DES-EDE-CBC

		// 1.2.840.113549.3.7 --> DES-EDE3-CBC
		m1.put( "1.2.840.113549.3.7", "DESede" );

		// 2.16.840.1.101.3.4.1.* --> aes variations

		OID_CIPHER_MAPPINGS = Collections.unmodifiableMap( m1 );
	}

	public static void main( String[] args ) throws Exception
	{
		FileInputStream in = new FileInputStream( args[ 0 ] );
		byte[] bytes = Util.streamToBytes( in );

		new PKCS8Key( bytes, "changeit".toCharArray() );
	}

	PKCS8Key( final byte[] encoded, char[] password )
	{
		List pemItems = PEMUtil.decode( encoded );
		byte[] derBytes = null;
		if ( pemItems.isEmpty() )
		{
			// must be DER encoded - PEMUtil wasn't able to extract anything.
			derBytes = encoded;
		}
		else
		{
			Iterator it = pemItems.iterator();
			while ( it.hasNext() )
			{
				PEMItem item = (PEMItem) it.next();
				String type = item.pemType.trim().toUpperCase();
				boolean unencryptedType = type.startsWith( UNENCRYPTED_PEM_TYPE );
				boolean encryptedType = type.startsWith( ENCRYPTED_PEM_TYPE );
				if ( unencryptedType || encryptedType )
				{
					if ( derBytes != null )
					{
						throw new RuntimeException( "more than one pkcs8 key found in supplied byte array!" );
					}
					derBytes = item.getDerBytes();
				}
			}
			// after the loop is finished, did we find anything?
			if ( derBytes == null )
			{
				throw new RuntimeException( "no pkcs8 key found in supplied byte array!" );
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
System.out.println( pkcs8 );

		String oid = pkcs8.oid1;
		boolean encrypted = !"1.2.840.113549.1.1.1".equals( oid );
		byte[] decryptedPKCS8 = encrypted ? null : derBytes;

		if ( encrypted )
		{
			try
			{
				decryptedPKCS8 = decrypt( pkcs8, password );
			}
			catch ( GeneralSecurityException gse )
			{
				throw new RuntimeException( gse );
			}
		}


		System.out.println( Certificates.toString( decryptedPKCS8 ) );

		/*
		  asn = new ASN1InputStream( rsaKey );
		  seq = (DERSequence) asn.readObject();
		  pkcs8 = new PKCS8();
		  analyzeASN1( seq, pkcs8, 0 );
		  */


		KeySpec spec = new PKCS8EncodedKeySpec( decryptedPKCS8 );
		PrivateKey pk = null;
		try
		{
			KeyFactory KF = KeyFactory.getInstance( "RSA" );
			pk = KF.generatePrivate( spec );
		}
		catch ( Exception e )
		{
			e.printStackTrace( System.out );
		}
		if ( pk != null )
		{
			System.out.println( PEMUtil.formatRSAPrivateKey( (RSAPrivateCrtKey) pk ) );
			// System.out.println( Certificates.toString( pk.getEncoded() ) );
		}
		

	}

	private byte[] decrypt( PKCS8Asn1Structure pkcs8, char[] password )
			throws NoSuchAlgorithmException, NoSuchPaddingException
	{
		boolean useKeyDeriverVersion1 = true;
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
		if ( "1.2.840.113549.1.5.1".equals( oid ) )
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
			oid = pkcs8.oid2;
		}
		
		if ( "1.2.840.113549.1.5.12".equals( oid ) )
		{
			useKeyDeriverVersion1 = false;
			hash = "HmacSHA1";
			oid = pkcs8.oid3;
		}

		// AES
		if ( oid.startsWith( "2.16.840.1.101.3.4.1" ) )
		{
			cipher = "AES";
			int x = oid.lastIndexOf( '.' );
			int finalDigit = Integer.parseInt( oid.substring( x + 1 ) );
System.out.println( "AES final digit: " + finalDigit );
			switch ( finalDigit % 10 )
			{
				case 1: mode = "ECB"; break; 
				case 2: mode = "CBC"; break;
				case 3: mode = "OFB"; break;
				case 4: mode = "CFB"; break;
				default: throw new RuntimeException( "Unknown AES final digit: " + finalDigit );
			}
			switch ( finalDigit / 10 )
			{
				case 0: keySize = 128; break;
				case 2: keySize = 192; break;
				case 4: keySize = 256; break;
				default: throw new RuntimeException( "Unknown AES final digit: " + finalDigit );
			}
		}

System.out.println( "using oid: " + oid );

		if ( OID_CIPHER_MAPPINGS.containsKey( oid ) )
		{
			cipher = (String) OID_CIPHER_MAPPINGS.get( oid );
			if ( "DESede".equalsIgnoreCase( cipher ) )
			{
				keySize = 192;
			}
		}


		// Is the cipher even available?
		Cipher c = Cipher.getInstance( cipher );
		System.out.println( cipher + " is available!" );

		String transformation = cipher + "/" + mode + "/PKCS5Padding";
System.out.println( "transformation: " + transformation );
System.out.println( "hash: " + hash );

		byte[] salt = pkcs8.salt1;
		int ic = pkcs8.iterationCount;
		byte[] pwd = new byte[password.length];
		for ( int i = 0; i < pwd.length; i++ )
		{
			pwd[ i ] = (byte) password[ i ];
		}		

		DerivedKey dk;
		if ( useKeyDeriverVersion1 )
		{
			MessageDigest md = MessageDigest.getInstance( hash );
			dk = deriveKeyV1( pwd, salt, ic, keySize, ivSize, md );
		}
		else
		{
			Mac mac = Mac.getInstance( hash );
			dk = deriveKeyV2( pwd, salt, ic, keySize, ivSize, mac );
		}
		SecretKey secret = new SecretKeySpec( dk.key, cipher );
		c = Cipher.getInstance( transformation );
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
			c.init( Cipher.DECRYPT_MODE, secret, ivParams );
			ByteArrayInputStream bIn = new ByteArrayInputStream( pkcs8.payload );
			InputStream in = new CipherInputStream( bIn, c );
			return Util.streamToBytes( in );
		}
		catch ( Exception e )
		{
			throw new RuntimeException( e );
		}
	}

	public static DerivedKey deriveKeyV1( byte[] password, byte[] salt,
	                                      int iterations, int keySizeInBits,
	                                      int ivSizeInBits, MessageDigest md )
	{
		if ( iterations <= 0 )
		{
			throw new IllegalArgumentException( "iteration count must be greater than 0" );
		}
		int keySize = keySizeInBits / 8;
		int ivSize = ivSizeInBits / 8;

		md.reset();
		md.update( password );
		byte[] result = md.digest( salt );
		for ( int i = 1; i < iterations; i++ )
		{
			result = md.digest( result );
		}

		byte[] key = new byte[ keySize ];
		byte[] iv = new byte[ ivSize ];

		System.arraycopy( result, 0, key, 0, key.length );
		System.arraycopy( result, key.length, iv, 0, iv.length );
		return new DerivedKey( key, iv );
	}

	public static DerivedKey deriveKeyV2( byte[] password, byte[] salt,
	                                      int iterations, int keySizeInBits,
	                                      int ivSizeInBits, Mac mac )
	{
		if ( iterations <= 0 )
		{
			throw new IllegalArgumentException( "iteration count must be greater than 0" );
		}
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

		int hLen = mac.getMacLength();
		int dkLen = keySize + ivSize;
		int l = ( dkLen + hLen - 1 ) / hLen;
		byte[] blockIndex = new byte[4];
		byte[] finalResult = new byte[l * hLen];
		for ( int i = 1; i <= l; i++ )
		{
			int offset = ( i - 1 ) * hLen;
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
			System.out.println( "BAD BAD BAD" );
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
				if ( obj instanceof DERObjectIdentifier )
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
				else if ( obj instanceof DEROctetString )
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
						if ( pkcs8.payload == null )
						{
							pkcs8.payload = octets;
						}
						str = "probably binary (length=" + octets.length + ")";
					}
					else
					{
						if ( octets.length % 8 == 0 && octets.length <= 64 )
						{
							if ( pkcs8.salt1 == null )
							{
								pkcs8.salt1 = octets;
							}
							else if ( pkcs8.salt2 == null )
							{
								pkcs8.salt2 = octets;
							}
							str = PEMUtil.bytesToHex( octets );
						}
						else
						{
							str = new String( oct.getOctets() );
						}
					}
				}
				else if ( obj instanceof DERInteger )
				{
					DERInteger dInt = (DERInteger) obj;
					BigInteger big = dInt.toBigInteger();
					if ( BIGGEST.compareTo( big ) >= 0 )
					{
						if ( pkcs8.iterationCount == 0 )
						{
							pkcs8.iterationCount = big.intValue();
						}
					}
					str = dInt.toBigInteger().toString();
				}
				else if ( obj instanceof DERPrintableString )
				{
					DERPrintableString dps = (DERPrintableString) obj;
					str = dps.getString();
				}
				System.out.println( name + ": [" + str + "]" );
			}
			else
			{
				analyzeASN1( obj, pkcs8, depth + 1 );
			}
		}
	}


	private static class PKCS8Asn1Structure
	{
		protected String oid1;
		protected String oid2;
		protected String oid3;
		protected byte[] salt1;
		protected byte[] salt2;
		protected int iterationCount;
		protected byte[] payload;

		public String toString()
		{
			StringBuffer buf = new StringBuffer( 256 );
			buf.append( "---------- pkcs8 ------------" );
			buf.append( "\noid1:  " );
			buf.append( oid1 );
			if ( oid2 != null )
			{
				buf.append( "\noid2:  " );
				buf.append( oid2 );
			}
			buf.append( "\nsalt1: " );
			if ( salt1 != null )
			{
				buf.append( PEMUtil.bytesToHex( salt1 ) );
			}
			else
			{
				buf.append( "[null]" );
			}
			buf.append( "\nic:    " );
			buf.append( Integer.toString( iterationCount ) );
			if ( oid2 != null )
			{
				buf.append( "\noid3:  " );
				buf.append( oid3 );
			}
			if ( oid2 != null )
			{
				buf.append( "\nsalt2: " );
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


}
