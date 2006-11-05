package org.apache.commons.ssl;

import java.util.Collections;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.TreeMap;

/**
 * @author Julius Davies
 * @since 13-Aug-2006
 */
public class PEMItem
{
	public final static String DEK_INFO = "dek-info";

	private final byte[] derBytes;
	public final String pemType;
	public final Map properties;

	public final String dekInfo;
	public final byte[] iv;
	public final String cipher;
	public final String mode;
	public final int keySizeInBits;

	public PEMItem( byte[] derBytes, String type )
	{
		this( derBytes, type, null );
	}

	public PEMItem( byte[] derBytes, String type, Map properties )
	{
		this.derBytes = derBytes;
		this.pemType = type;
		if ( properties == null )
		{
			properties = new TreeMap(); // empty map
		}
		this.properties = Collections.unmodifiableMap( properties );
		String di = (String) properties.get( DEK_INFO );
		String diCipher = "";
		String diIV = "";
		if ( di != null )
		{
			StringTokenizer st = new StringTokenizer( di, "," );
			if ( st.hasMoreTokens() )
			{
				diCipher = st.nextToken().trim().toLowerCase();
			}
			if ( st.hasMoreTokens() )
			{
				diIV = st.nextToken().trim().toLowerCase();
			}
		}
		this.dekInfo = diCipher;
		this.iv = PEMUtil.hexToBytes( diIV );
		if ( !"".equals( diCipher ) )
		{
			this.mode = dekInfo.substring( dekInfo.length() - 3 ).toUpperCase();
			if ( dekInfo.startsWith( "des-cbc" ) )
			{
				cipher = "DES";
				keySizeInBits = 64;
			}
			else if ( dekInfo.startsWith( "des-ede3" ) )
			{
				cipher = "DESede";
				keySizeInBits = 192;
			}
			else if ( dekInfo.startsWith( "aes-" ) )
			{
				String keySize = dekInfo.substring( 4, 7 );
				cipher = "AES";
				keySizeInBits = Integer.parseInt( keySize );
			}
			else
			{
				cipher = "UNKNOWN";
				keySizeInBits = -1;
			}
		}
		else
		{
			this.mode = "";
			cipher = "UNKNOWN";
			keySizeInBits = -1;
		}

	}

	public byte[] getDerBytes()
	{
		byte[] b = new byte[derBytes.length];
		System.arraycopy( derBytes, 0, b, 0, derBytes.length );
		return b;
	}

}
