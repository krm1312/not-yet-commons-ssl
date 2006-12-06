package org.apache.commons.ssl;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.StringTokenizer;

/**
 * Class for encrypting or decrypting data with a password (PBE - password
 * based encryption).  Compatible with "openssl enc" unix utility.
 * <p>
 * This class is able to decrypt files encrypted with "openssl" unix utility.
 * <p>
 * The "openssl" unix utility is able to decrypt files encrypted by this class.
 * <p>
 * This class is also able to encrypt and decrypt its own files.
 *  
 *
 * @author Julius Davies
 * @since 5-Dec-2006
 */
public class OpenSSL
{

	/**
     * Decrypts data using a password and an OpenSSL compatible cipher
     * name.
     *
	 * @param cipher  The OpenSSL compatible cipher to use (try "man enc" on a
	 *        unix box to see what's possible).  Some examples:
	 *              <ul><li>des, des3, des-ede3-cbc
	 *              <li>aes128, aes192, aes256, aes-256-cbc
	 *              <li>rc2, rc4, bf</ul>
	 *
	 *
	 * @param pwd  password to use for this PBE decryption
	 * @param encrypted  InputStream to decrypt.  Can be raw, or base64.
	 * @return decrypted bytes as an InputStream
	 * @throws IOException problems with InputStream
	 * @throws GeneralSecurityException problems decrypting
	 */
	public static InputStream decrypt( String cipher, byte[] pwd,
	                                   InputStream encrypted )
			throws IOException, GeneralSecurityException
	{
		CipherInfo cipherInfo = lookup( cipher );
		MessageDigest md5 = MessageDigest.getInstance( "MD5" );
		boolean salted = false;

		// First 16 bytes of raw binary will hopefully be OpenSSL's
		// "Salted__[8 bytes of hex]" thing.  Might be in Base64, though.
		byte[] saltLine = Util.streamToBytes( encrypted, 16 );
		if ( saltLine.length <= 0 )
		{
			throw new IOException( "encrypted InputStream is empty" );
		}
		String firstEightBytes = "";
		if ( saltLine.length >= 8 )
		{
			firstEightBytes = new String( saltLine, 0, 8 );
		}
		if ( "SALTED__".equalsIgnoreCase( firstEightBytes ) )
		{
			salted = true;
		}
		else
		{
			// Maybe the reason we didn't find the salt is because we're in
			// base64.
			if ( Base64.isArrayByteBase64( saltLine ) )
			{
				InputStream head = new ByteArrayInputStream( saltLine );
				// Need to put that 16 byte "saltLine" back into the Stream.
				encrypted = new ComboInputStream( head, encrypted );
				encrypted = new Base64InputStream( encrypted, true );
				saltLine = Util.streamToBytes( encrypted, 16 );

				if ( saltLine.length >= 8 )
				{
					firstEightBytes = new String( saltLine, 0, 8 );
				}
				if ( "SALTED__".equalsIgnoreCase( firstEightBytes ) )
				{
					salted = true;
				}
			}
		}

		byte[] salt = null;
		if ( salted )
		{
			salt = new byte[8];
			System.arraycopy( saltLine, 8, salt, 0, 8 );
		}
		else
		{
            // Encrypted data wasn't salted.  Need to put the "saltLine" we
            // extracted back into the stream.
            InputStream head = new ByteArrayInputStream( saltLine );
			encrypted = new ComboInputStream( head, encrypted );
		}

		int keySize = cipherInfo.keySize;
		int ivSize = 64;
		if ( cipherInfo.javaCipher.startsWith( "AES" ) )
		{
			ivSize = 128;
		}

		DerivedKey dk = deriveKey( pwd, salt, keySize, ivSize, md5 );
		Cipher c = PKCS8Key.generateCipher( cipherInfo.javaCipher,
		                                    cipherInfo.blockMode,
		                                    dk, cipherInfo.des2, null, true );

		return new CipherInputStream( encrypted, c );
	}

    public static InputStream encrypt( String cipher, byte[] pwd,
                                       InputStream data )
            throws IOException, GeneralSecurityException
    {
        // base64 is the default output format.
        return encrypt( cipher, pwd, data, true );
    }

    public static InputStream encrypt( String cipher, byte[] pwd,
                                       InputStream data, boolean toBase64 )
            throws IOException, GeneralSecurityException
    {
        // we use a salt by default.
        return encrypt( cipher, pwd, data, toBase64, true );
    }

    /**
     * Encrypts data using a password and an OpenSSL compatible cipher
     * name.
     *
	 * @param cipher  The OpenSSL compatible cipher to use (try "man enc" on a
	 *        unix box to see what's possible).  Some examples:
	 *              <ul><li>des, des3, des-ede3-cbc
	 *              <li>aes128, aes192, aes256, aes-256-cbc
	 *              <li>rc2, rc4, bf</ul>
	 *
	 *
	 * @param pwd  password to use for this PBE encryption
	 * @param data  InputStream to encrypt
	 * @param toBase64  true if resulting InputStream should contain base64,
	 *                  <br>false if InputStream should contain raw binary.
	 * @param useSalt   true if a salt should be used to derive the key.
     *                  <br>false otherwise.  (Best security practises
     *                  always recommend using a salt!). 
     *
	 * @return encrypted bytes as an InputStream.  First 16 bytes include the
	 *         special OpenSSL "Salted__" info if <code>useSalt</code> is true.
	 * @throws IOException problems with the data InputStream
	 * @throws GeneralSecurityException problems encrypting
	 */
	public static InputStream encrypt( String cipher, byte[] pwd,
	                                   InputStream data, boolean toBase64,
                                       boolean useSalt )
			throws IOException, GeneralSecurityException
	{
		CipherInfo cipherInfo = lookup( cipher );
		MessageDigest md5 = MessageDigest.getInstance( "MD5" );
        byte[] salt = null;
        if ( useSalt )
        {
            SecureRandom rand = SecureRandom.getInstance( "SHA1PRNG" );
            salt = new byte[8];
            rand.nextBytes( salt );
        }

        int keySize = cipherInfo.keySize;
		int ivSize = 64;
		if ( cipherInfo.javaCipher.startsWith( "AES" ) )
		{
			ivSize = 128;
		}

		DerivedKey dk = deriveKey( pwd, salt, keySize, ivSize, md5 );
		Cipher c = PKCS8Key.generateCipher( cipherInfo.javaCipher,
		                                    cipherInfo.blockMode,
		                                    dk, cipherInfo.des2, null, false );

		InputStream cipherStream = new CipherInputStream( data, c );

        if ( useSalt )
        {
            byte[] saltLine = new byte[16];
            byte[] salted = "Salted__".getBytes();
            System.arraycopy( salted, 0, saltLine, 0, salted.length );
            System.arraycopy( salt, 0, saltLine, salted.length, salt.length );            
            InputStream head = new ByteArrayInputStream( saltLine );
            cipherStream = new ComboInputStream( head, cipherStream );
        }
        if ( toBase64 )
		{
			cipherStream = new Base64InputStream( cipherStream, false );
		}
		return cipherStream;
	}

	public static DerivedKey deriveKey( byte[] password, byte[] salt,
	                                    int keySize, MessageDigest md )
	{
		return deriveKey( password, salt, keySize, 0, md );
	}

	public static DerivedKey deriveKey( byte[] password, byte[] salt,
	                                    int keySize, int ivSize,
	                                    MessageDigest md )
	{
		md.reset();
		byte[] keyAndIv = new byte[( keySize / 8 ) + ( ivSize / 8 )];
		if ( salt == null || salt.length == 0 )
		{
			// Unsalted!  Bad idea!
			salt = null;
		}
		byte[] result;
		int currentPos = 0;
		while ( currentPos < keyAndIv.length )
		{
			md.update( password );
			if ( salt != null )
			{
				// First 8 bytes of salt ONLY!  That wasn't obvious to me
                // when using AES encrypted private keys in "Traditional
                // SSLeay Format".
                //
                // Example:
                // DEK-Info: AES-128-CBC,8DA91D5A71988E3D4431D9C2C009F249
                //
                // Only the first 8 bytes are salt, but the whole thing is
                // re-used again later as the IV.  MUCH gnashing of teeth!
                md.update( salt, 0, 8 );
			}
			result = md.digest();
			int stillNeed = keyAndIv.length - currentPos;
			// Digest gave us more than we need.  Let's truncate it.
			if ( result.length > stillNeed )
			{
				byte[] b = new byte[stillNeed];
				System.arraycopy( result, 0, b, 0, b.length );
				result = b;
			}
			System.arraycopy( result, 0, keyAndIv, currentPos, result.length );
			currentPos += result.length;
			if ( currentPos < keyAndIv.length )
			{
				// Next round starts with a hash of the hash.
				md.reset();
				md.update( result );
			}
		}
		if ( ivSize == 0 )
		{
            // if ivSize == 0, then "keyAndIv" array is actually all key.

            // Must be "Traditional SSLeay Format" encrypted private key in
            // PEM.  The "salt" in its entirety (not just first 8 bytes) will
            // probably be re-used later as the IV (initialization vector). 
            return new DerivedKey( keyAndIv, salt );
		}
		else
		{
			byte[] key = new byte[keySize / 8];
			byte[] iv = new byte[ivSize / 8];
			System.arraycopy( keyAndIv, 0, key, 0, key.length );
			System.arraycopy( keyAndIv, key.length, iv, 0, iv.length );
			return new DerivedKey( key, iv );
		}
	}


	public static class CipherInfo
	{
		public final String javaCipher;
		public final String blockMode;
		public final int keySize;
		public final boolean des2;

		public CipherInfo( String javaCipher, String blockMode, int keySize,
		                   boolean des2 )
		{
			this.javaCipher = javaCipher;
			this.blockMode = blockMode;
			this.keySize = keySize;
			this.des2 = des2;
		}

		public String toString()
		{
			return javaCipher + "/" + blockMode + " " + keySize + "bit  des2=" + des2;
		}
	}

	/**
	 * Converts the way OpenSSL names its ciphers into a Java-friendly naming.
	 *  
	 * @param openSSLCipher OpenSSL cipher name, e.g. "des3" or "des-ede3-cbc".
	 *        Try "man enc" on a unix box to see what's possible.
	 *
	 * @return CipherInfo object with the Java-friendly cipher information.
	 */
	public static CipherInfo lookup( String openSSLCipher )
	{
		openSSLCipher = openSSLCipher.trim();
		if ( openSSLCipher.charAt( 0 ) == '-' )
		{
			openSSLCipher = openSSLCipher.substring( 1 );
		}
		String javaCipher = openSSLCipher;
		String blockMode = "CBC";
		int keySize = -1;
		boolean des2 = false;


		StringTokenizer st = new StringTokenizer( openSSLCipher, "-" );
		if ( st.hasMoreTokens() )
		{
			javaCipher = st.nextToken().toUpperCase();
			if ( st.hasMoreTokens() )
			{
				// Is this the middle token?  Or the last token?
				String tok = st.nextToken();
				if ( st.hasMoreTokens() )
				{
					try
					{
						keySize = Integer.parseInt( tok );
					}
					catch ( NumberFormatException nfe )
					{
						// I guess 2nd token isn't an integer
						String upper = tok.toUpperCase();
						if ( "EDE3".equals( upper ) )
						{
							javaCipher = "DESede";
						}
						if ( "EDE".equals( upper ) )
						{
							javaCipher = "DESede";
							des2 = true;
						}
					}
					blockMode = st.nextToken().toUpperCase();
				}
				else
				{
					// It's the last token, so must be mode (usually "CBC").
					blockMode = tok.toUpperCase();
					if ( "EDE".equals( blockMode ) )
					{
						javaCipher = "DESede";
						blockMode = "ECB";
						des2 = true;
					}
					else if ( "EDE3".equals( blockMode ) )
					{
						javaCipher = "DESede";
						blockMode = "ECB";
					}
				}
			}
		}
		if ( "BF".equals( javaCipher ) )
		{
			javaCipher = "Blowfish";
		}

		if ( "DES3".equals( javaCipher ) )
		{
			javaCipher = "DESede";
		}
		else if ( "DES2".equals( javaCipher ) )
		{
			javaCipher = "DESede";
			des2 = true;
		}
		else if ( "AES128".equals( javaCipher ) )
		{
			javaCipher = "AES";
			keySize = 128;
		}
		else if ( "AES192".equals( javaCipher ) )
		{
			javaCipher = "AES";
			keySize = 192;
		}
		else if ( "AES256".equals( javaCipher ) )
		{
			javaCipher = "AES";
			keySize = 256;
		}


		if ( keySize == -1 )
		{
			if ( javaCipher.startsWith( "DESede" ) )
			{
				keySize = 192;
			}
			else if ( javaCipher.startsWith( "DES" ) )
			{
				keySize = 64;
			}
			else
			{
				// RC2, RC4, and Blowfish ?
				keySize = 128;
			}
		}

		return new CipherInfo( javaCipher, blockMode, keySize, des2 );
	}


	/**
	 *
	 * @param args command line arguments: [password] [cipher] [file-to-decrypt]
	 *        <br>[cipher] == OpenSSL cipher name, e.g. "des3" or "des-ede3-cbc".
	 *        Try "man enc" on a unix box to see what's possible.
	 *
	 * @throws IOException  problems with the [file-to-decrypt]
	 * @throws GeneralSecurityException  decryption problems
	 */
	public static void main( String[] args )
			throws IOException, GeneralSecurityException
	{
        if ( args.length < 3 )
		{
			System.out.println( Version.versionString() );
			System.out.println( "Pure-java utility to decrypt files previously encrypted by \'openssl enc\'" );
			System.out.println();
			System.out.println( "Usage:  java -cp commons-ssl.jar org.apache.commons.ssl.OpenSSL [args]" );
			System.out.println( "        [args]   == [password] [cipher] [file-to-decrypt]" );
			System.out.println( "        [cipher] == des, des3, des-ede3-cbc, aes256, rc2, rc4, bf, bf-cbc, etc..." );
            System.out.println( "                    Try 'man enc' on a unix box to see what's possible." );
			System.out.println();
			System.out.println( "This utility can handle base64 or raw, salted or unsalted." );
			System.out.println();
			System.exit( 1 );
		}
		char[] password = args[ 0 ].toCharArray();
		byte[] pwdAsBytes = new byte[password.length];
		for ( int i = 0; i < password.length; i++ )
		{
			pwdAsBytes[ i ] = (byte) password[ i ];
		}

		InputStream in = new FileInputStream( args[ 2 ] );
		in = decrypt( args[ 1 ], pwdAsBytes, in );

		// in = encrypt( args[ 1 ], pwdAsBytes, in, true );		

		Util.pipeStream( in, System.out, false );
		byte[] output = Util.streamToBytes( in );
		System.out.write( output );
		System.out.flush();
	}

}
