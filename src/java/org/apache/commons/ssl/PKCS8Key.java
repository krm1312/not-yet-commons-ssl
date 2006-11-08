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
import java.security.PrivateKey;
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
	public final static Map OID_HASH_MAPPINGS;
	public final static Map OID_CIPHER_MAPPINGS;
	public final static Map OID_MODE_MAPPINGS;
	public final static Map OID_SIZE_MAPPINGS;

	public final static String UNENCRYPTED_PEM_TYPE = "PRIVATE KEY";
	public final static String ENCRYPTED_PEM_TYPE = "ENCRYPTED PRIVATE KEY";

	static
	{
		Map m1 = new TreeMap();
		Map m2 = new TreeMap();
		Map m3 = new TreeMap();
		Map m4 = new TreeMap();

		// 1.2.840.113549.1.5.3 --> pbeWithMD5AndDES-CBC
		m1.put( "1.2.840.113549.1.5.3", "MD5" );
		m2.put( "1.2.840.113549.1.5.3", "DES" );
		m3.put( "1.2.840.113549.1.5.3", "CBC" );
		m4.put( "1.2.840.113549.3.7", "64" );

		// 1.3.14.3.2.7  --> DES-EDE-CBC
		m1.put( "1.3.14.3.2.7", "HmacSHA1" );
		m2.put( "1.3.14.3.2.7", "DES" );
		m3.put( "1.3.14.3.2.7", "CBC" );
		m4.put( "1.3.14.3.2.7", "64" );

		// 1.2.840.113549.3.7 --> DES-EDE3-CBC
		m1.put( "1.2.840.113549.3.7", "HmacSHA1" );
		m2.put( "1.2.840.113549.3.7", "DESede" );
		m3.put( "1.2.840.113549.3.7", "CBC" );
		m4.put( "1.2.840.113549.3.7", "192" );		
		
		// 2.16.840.1.101.3.4.1.2 --> aes128-CBC
		m1.put( "2.16.840.1.101.3.4.1.2", "HmacSHA1" );
		m2.put( "2.16.840.1.101.3.4.1.2", "AES" );
		m3.put( "2.16.840.1.101.3.4.1.2", "CBC" );
		m4.put( "2.16.840.1.101.3.4.1.2", "128" );		

		OID_HASH_MAPPINGS = Collections.unmodifiableMap( m1 );
		OID_CIPHER_MAPPINGS = Collections.unmodifiableMap( m2 );
		OID_MODE_MAPPINGS = Collections.unmodifiableMap( m3 );
		OID_SIZE_MAPPINGS = Collections.unmodifiableMap( m4 );
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

		byte[] decryptedPKCS8 = null;

		String oid = pkcs8.oid1;
		if ( "1.2.840.113549.1.5.13".equals( oid ) )
		{
			oid = pkcs8.oid2;
		}
		if ( "1.2.840.113549.1.5.12".equals( oid ) )
		{
			oid = pkcs8.oid3;
		}

		System.out.println( "using oid: " + oid );
		String hash = (String) OID_HASH_MAPPINGS.get( oid );

		String cipher = (String) OID_CIPHER_MAPPINGS.get( oid );
		String mode = (String) OID_MODE_MAPPINGS.get( oid );
		String transformation = cipher + "/" + mode + "/PKCS5Padding";
System.out.println( "transformation: " + transformation );
System.out.println( "hash: " + hash );		
		int keySize = Integer.parseInt( (String) OID_SIZE_MAPPINGS.get( oid ) );

		byte[] salt = pkcs8.salt1;
		int ic = pkcs8.iterationCount;

		try
		{
			Mac mac = Mac.getInstance( hash );
			DerivedKey dk = deriveKeyV2( password, salt, ic, keySize, 64, mac );
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
			c.init( Cipher.DECRYPT_MODE, secret, ivParams );
			ByteArrayInputStream bIn = new ByteArrayInputStream( pkcs8.payload );
			InputStream in = new CipherInputStream( bIn, c );
			decryptedPKCS8 = Util.streamToBytes( in );
		}
		catch ( Exception e )
		{
			e.printStackTrace( System.out );
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


	public static DerivedKey deriveKeyV2( char[] password, byte[] salt,
	                                      int iterations, int keySizeInBits,
	                                      int ivSizeInBits, Mac mac )
	{
		if ( iterations <= 0 )
		{
			throw new IllegalArgumentException( "iteration count must be greater than 0" );
		}

		int keySize = keySizeInBits / 8;
		int ivSize = ivSizeInBits / 8;
		byte[] pass = new byte[password.length];
		for ( int i = 0; i < pass.length; i++ )
		{
			pass[ i ] = (byte) password[ i ];
		}
		try
		{
			SecretKeySpec key = new SecretKeySpec( pass, "N/A" );
			mac.init( key );
		}
		catch ( InvalidKeyException ike )
		{
			throw new RuntimeException( ike );
		}		

		int hLen = mac.getMacLength();
		int dkLen = keySize + ivSize;
System.out.println( "dkLen: " + dkLen );		
		int l = ( dkLen + hLen - 1 ) / hLen;
System.out.println( "l: " + l );		
		byte[] iBuf = new byte[4];
		byte[] out = new byte[l * hLen];
		for ( int i = 1; i <= l; i++ )
		{
			iBuf[ 0 ] = (byte) ( i >>> 24 );
			iBuf[ 1 ] = (byte) ( i >>> 16 );
			iBuf[ 2 ] = (byte) ( i >>> 8 );
			iBuf[ 3 ] = (byte) i;
System.out.println( iBuf[ 0 ] + " " + iBuf[ 1 ] + " " + iBuf[ 2 ] + " " + iBuf[ 3 ] );			
			F( pass, salt, iterations, iBuf, out, ( i - 1 ) * hLen, mac );
for ( int j = 0; j < out.length; j++ )
{
	System.out.print( out[ j ] + " " );
}
System.out.println();			
		}

		System.out.println( "out.length: " + out.length );
		byte[] key = new byte[keySize];
		byte[] iv = new byte[ivSize];
		System.out.println( "key.length: " + key.length );
		System.out.println( "iv.length: " + iv.length );				
		System.arraycopy( out, 0, key, 0, key.length );
		System.arraycopy( out, key.length, iv, 0, iv.length );
		return new DerivedKey( key, iv );
	}

	private static void F( byte[] P, byte[] S, int c, byte[] iBuf, byte[] out,
	                       int outOff, Mac mac )
	{
		mac.reset();
		//mac.update( P );
		mac.update( S );
		mac.update( iBuf );		
		byte[] result = mac.doFinal();
		System.arraycopy( result, 0, out, outOff, result.length );
		for ( int count = 1; count < c; count++ )
		{
			mac.reset();
			//mac.update( P );
			mac.update( result );
			result = mac.doFinal();
			for ( int j = 0; j != result.length; j++ )
			{
				out[ outOff + j ] ^= result[ j ];
			}
		}
	}

	public static DerivedKey deriveKey( char[] password, byte[] salt,
	                                    int keySize, MessageDigest md, Mac mac,
	                                    int iterations )
	{
		if ( md != null )
		{
			md.reset();
		}
		else
		{
			mac.reset();
		}


		byte[] key = new byte[keySize / 8];
		byte[] pwd = new byte[password.length];
		for ( int i = 0; i < pwd.length; i++ )
		{
			pwd[ i ] = (byte) password[ i ];
		}

		byte[] result = null;
		for ( int i = 0; i < iterations; i++ )
		{
			if ( md != null )
			{
				md.update( pwd );
				result = md.digest( salt );
			}
			else
			{
				mac.update( pwd );
				result = mac.doFinal( salt );
			}
		}


		System.arraycopy( result, 0, key, 0, key.length );
		System.arraycopy( result, 8, salt, 0, 8 );
		return null;
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
						if ( octets.length % 8 == 0 && octets.length <= 32 )
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
			buf.append( PEMUtil.bytesToHex( salt1 ) );
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
				buf.append( PEMUtil.bytesToHex( salt2 ) );
			}
			return buf.toString();
		}
	}


}
