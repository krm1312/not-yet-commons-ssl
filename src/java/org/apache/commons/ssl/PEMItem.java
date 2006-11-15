/*
 * $Header$
 * $Revision$
 * $Date$
 *
 * ====================================================================
 *
 *  Copyright 2006 The Apache Software Foundation
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */

package org.apache.commons.ssl;

import java.util.Collections;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.TreeMap;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
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
	public final boolean des2;
	public final String mode;
	public final int keySizeInBits;

	public PEMItem( byte[] derBytes, String type )
	{
		this( derBytes, type, null );
	}

	public PEMItem( byte[] derBytes, String type, Map properties )
	{
		boolean doubleDES = false;
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
			String CIPHER = "UNKNOWN";
			String MODE = "";
			int keySize = -1;
			StringTokenizer st = new StringTokenizer( dekInfo, "-" );
			if ( st.hasMoreTokens() )
			{
				CIPHER = st.nextToken().toUpperCase();
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
								CIPHER = "DESede";
							}
							if ( "EDE".equals( upper ) )
							{
								CIPHER = "DESede";
								doubleDES = true;
							}
						}
						MODE = st.nextToken().toUpperCase();
					}
					else
					{
						// It's the last token, so must be mode (usually "CBC").
						MODE = tok.toUpperCase();
						if ( "EDE".equals( MODE ) )
						{
							CIPHER = "DESede";
							MODE = "ECB";
							doubleDES = true;
						}
						else if ( "EDE3".equals( MODE ) )
						{
							CIPHER = "DESede";
							MODE = "ECB";
						}
					}
				}
			}
			if ( "BF".equals( CIPHER ) )
			{
				CIPHER = "Blowfish";
			}
			

			this.mode = MODE;
			this.cipher = CIPHER;
			if ( keySize == -1 )
			{
				if ( CIPHER.startsWith( "DESede" ) )
				{
					keySizeInBits = 192;
				}
				else if ( CIPHER.startsWith( "DES" ) )
				{
					keySizeInBits = 64;
				}
				else
				{
					// RC2, RC4, and Blowfish ?
					keySizeInBits = 128;
				}
			}
			else
			{
				keySizeInBits = keySize;
			}
		}
		else
		{
			this.mode = "";
			cipher = "UNKNOWN";
			keySizeInBits = -1;
		}
		this.des2 = doubleDES;
	}

	public byte[] getDerBytes()
	{
		byte[] b = new byte[derBytes.length];
		System.arraycopy( derBytes, 0, b, 0, derBytes.length );
		return b;
	}

}
