package org.apache.commons.ssl;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * @author Julius Davies
 * @since 13-Aug-2006
 */
public class PEMUtil
{
	final static String LINE_SEPARATOR = System.getProperty( "line.separator" );

	public static List decode( byte[] pemBytes )
	{
		LinkedList pemItems = new LinkedList();
		ByteArrayInputStream in = new ByteArrayInputStream( pemBytes );
		String line = Util.readLine( in );
		while ( line != null )
		{
			int len = 0;
			byte[] decoded = null;
			ArrayList listOfByteArrays = new ArrayList( 64 );
			Map properties = new HashMap();
			String type = "[unknown]";
			while ( line != null && !beginBase64( line ) )
			{
				line = Util.readLine( in );
			}
			if ( line != null )
			{
				String upperLine = line.toUpperCase();
				int x = upperLine.indexOf( "-BEGIN" ) + "-BEGIN".length();
				int y = upperLine.indexOf( "-", x );
				type = upperLine.substring( x, y ).trim();
				line = Util.readLine( in );
			}
			while ( line != null && !endBase64( line ) )
			{
				line = Util.trim( line );
				if ( !"".equals( line ) )
				{
					int x = line.indexOf( ':' );
					if ( x > 0 )
					{
						String k = line.substring( 0, x ).trim();
						String v = "";
						if ( line.length() > x + 1 )
						{
							v = line.substring( x + 1 ).trim();
						}
						properties.put( k.toLowerCase(), v.toLowerCase() );
					}
					else
					{
						byte[] base64 = line.getBytes();
						byte[] rawBinary = Base64.decodeBase64( base64 );
						listOfByteArrays.add( rawBinary );
						len += rawBinary.length;
					}
				}
				line = Util.readLine( in );
			}
			if ( line != null )
			{
				line = Util.readLine( in );
			}

			if ( !listOfByteArrays.isEmpty() )
			{
				decoded = new byte[len];
				int pos = 0;
				Iterator it = listOfByteArrays.iterator();
				while ( it.hasNext() )
				{
					byte[] oneLine = (byte[]) it.next();
					System.arraycopy( oneLine, 0, decoded, pos, oneLine.length );
					pos += oneLine.length;
				}
				PEMItem item = new PEMItem( decoded, type, properties );
				pemItems.add( item );
			}
		}

		// closing ByteArrayInputStream is a NO-OP
		// in.close();

		return pemItems;
	}

	private static boolean beginBase64( String line )
	{
		line = line != null ? line.trim().toUpperCase() : "";
		int x = line.indexOf( "-BEGIN" );
		return x > 0 && startsAndEndsWithDashes( line );
	}

	private static boolean endBase64( String line )
	{
		line = line != null ? line.trim().toUpperCase() : "";
		int x = line.indexOf( "-END" );
		return x > 0 && startsAndEndsWithDashes( line );
	}

	private static boolean startsAndEndsWithDashes( String line )
	{
		line = Util.trim( line );
		char c = line.charAt( 0 );
		char d = line.charAt( line.length() - 1 );
		return c == '-' && d == '-';
	}

	public static String formatRSAPrivateKey( RSAPrivateCrtKey key )
	{
		StringBuffer buf = new StringBuffer( 2048 );
		buf.append( "Private-Key:" );
		buf.append( LINE_SEPARATOR );
		buf.append( "modulus:" );
		buf.append( LINE_SEPARATOR );
		buf.append( formatBigInteger( key.getModulus(), 129 * 2 ) );
		buf.append( LINE_SEPARATOR );
		buf.append( "publicExponent: " );
		buf.append( key.getPublicExponent() );
		buf.append( LINE_SEPARATOR );
		buf.append( "privateExponent:" );
		buf.append( LINE_SEPARATOR );
		buf.append( formatBigInteger( key.getPrivateExponent(), 128 * 2 ) );
		buf.append( LINE_SEPARATOR );
		buf.append( "prime1:" );
		buf.append( LINE_SEPARATOR );
		buf.append( formatBigInteger( key.getPrimeP(), 65 * 2 ) );
		buf.append( LINE_SEPARATOR );
		buf.append( "prime2:" );
		buf.append( LINE_SEPARATOR );
		buf.append( formatBigInteger( key.getPrimeQ(), 65 * 2 ) );
		buf.append( LINE_SEPARATOR );
		buf.append( "exponent1:" );
		buf.append( LINE_SEPARATOR );
		buf.append( formatBigInteger( key.getPrimeExponentP(), 65 * 2 ) );
		buf.append( LINE_SEPARATOR );
		buf.append( "exponent2:" );
		buf.append( LINE_SEPARATOR );
		buf.append( formatBigInteger( key.getPrimeExponentQ(), 65 * 2 ) );
		buf.append( LINE_SEPARATOR );
		buf.append( "coefficient:" );
		buf.append( LINE_SEPARATOR );
		buf.append( formatBigInteger( key.getCrtCoefficient(), 65 * 2 ) );
		return buf.toString();
	}

	public static String formatBigInteger( BigInteger bi, int length )
	{
		String s = bi.toString( 16 );
		StringBuffer buf = new StringBuffer( s.length() );
		int zeroesToAppend = length - s.length();
		int count = 0;
		buf.append( "    " );
		for ( int i = 0; i < zeroesToAppend; i++ )
		{
			count++;
			buf.append( '0' );
			if ( i % 2 == 1 )
			{
				buf.append( ':' );
			}
		}
		for ( int i = 0; i < s.length() - 2; i++ )
		{
			count++;
			buf.append( s.charAt( i ) );
			if ( i % 2 == 1 )
			{
				buf.append( ':' );
			}
			if ( count % 30 == 0 )
			{
				buf.append( LINE_SEPARATOR );
				buf.append( "    " );
			}
		}
		buf.append( s.substring( s.length() - 2 ) );
		return buf.toString();
	}

	public static byte[] hexToBytes( String s )
	{
		byte[] b = new byte[s.length() / 2];
		for ( int i = 0; i < b.length; i++ )
		{
			String hex = s.substring( 2 * i, 2 * ( i + 1 ) );
			b[ i ] = (byte) Integer.parseInt( hex, 16 );
		}
		return b;
	}

	public static String bytesToHex( byte[] b )
	{
		return bytesToHex( b, 0, b.length );
	}

	public static String bytesToHex( byte[] b, int offset, int length )
	{
		StringBuffer buf = new StringBuffer();
		int len = Math.min( offset + length, b.length );
		for ( int i = offset; i < len; i++ )
		{
			int c = (int) b[ i ];
			if ( c < 0 )
			{
				c = c + 256;
			}
			if ( c >= 0 && c <= 15 )
			{
				buf.append( '0' );
			}
			buf.append( Integer.toHexString( c ) );
		}
		return buf.toString();
	}

	/*
	public static void main( String[] args ) throws Exception
	{
		FileInputStream fin = new FileInputStream( args[ 0 ] );
		byte[] pemBytes = Util.streamToBytes( fin );
		PEMItem item = (PEMItem) decode( pemBytes ).get( 0 );
		String transformation = item.cipher + "/" + item.mode + "/PKCS5Padding";
		System.out.println( item.properties );
		System.out.println( transformation );
		System.out.println( "key size: " + item.keySizeInBits );

		char[] pwd = "dude".toCharArray();
		byte[] key = ssleayCreateKey( pwd, item.iv, item.keySizeInBits );

		SecretKey sk = new SecretKeySpec( key, item.cipher );
		IvParameterSpec ivParams = new IvParameterSpec( item.iv );

		byte[] input = item.getDerBytes();
		Cipher c = Cipher.getInstance( transformation );
		c.init( Cipher.DECRYPT_MODE, sk, ivParams );
		InputStream in = new ByteArrayInputStream( input );
		in = new CipherInputStream( in, c );

		byte[] b = Util.streamToBytes( in );
		System.out.println( Certificates.toString( b ) );
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
	*/
}
