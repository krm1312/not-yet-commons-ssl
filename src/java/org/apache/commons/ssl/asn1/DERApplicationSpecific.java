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


import java.io.ByteArrayOutputStream;
import java.io.IOException;


/**
 * DER Application Specific object.
 */
public class DERApplicationSpecific extends DERObject
{
	private int tag;


	/**
	 * Basic DERObject constructor.
	 */
	public DERApplicationSpecific( int tag, byte[] value )
	{
		super( tag, value );
		this.tag = tag;
	}


	/**
	 * Static factory method, type-conversion operator.
	 */
	public static DERApplicationSpecific valueOf( int tag, DEREncodable object ) throws IOException
	{
		tag = tag | CONSTRUCTED;

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ASN1OutputStream aos = new ASN1OutputStream( baos );

		aos.writeObject( object );

		return new DERApplicationSpecific( tag, baos.toByteArray() );
	}


	public int getApplicationTag()
	{
		return tag & 0x1F;
	}


	public DEREncodable getObject() throws IOException
	{
		return new ASN1InputStream( getOctets() ).readObject();
	}


	public void encode( ASN1OutputStream out ) throws IOException
	{
		out.writeEncoded( APPLICATION | tag, value );
	}
}
