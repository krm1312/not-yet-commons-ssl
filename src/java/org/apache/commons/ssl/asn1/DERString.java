/*
 * $HeadURL:  $
 * $Revision$
 * $Date$
 *
 * ====================================================================
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */

package org.apache.commons.ssl.asn1;


import java.io.UnsupportedEncodingException;


/**
 * Interface for DER string objects.
 */
public abstract class DERString extends DERObject
{
	/**
	 * Basic DERObject constructor.
	 */
	DERString( int tag, byte[] value )
	{
		super( tag, value );
	}


	/**
	 * Lazy accessor.
	 *
	 * @return underlying byte array converted to a String
	 */
	public String getString()
	{
		return byteArrayToString( value );
	}


	/**
	 * Utility method for converting byte arrays to Strings.
	 *
	 * @param bytes
	 * @return String
	 */
	protected static String byteArrayToString( byte[] bytes )
	{
		try
		{
			return new String( bytes, "UTF-8" );
		}
		catch ( UnsupportedEncodingException uee )
		{
			return "";
		}
	}


	/**
	 * Utility method for converting Strings to bytes.
	 *
	 * @param string
	 * @return bytes
	 */
	protected static byte[] stringToByteArray( String string )
	{
		try
		{
			return string.getBytes( "UTF-8" );
		}
		catch ( UnsupportedEncodingException uee )
		{
			return new byte[]
					{ };
		}
	}
}
