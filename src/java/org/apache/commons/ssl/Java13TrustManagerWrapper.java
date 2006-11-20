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

import com.sun.net.ssl.X509TrustManager;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 30-Jun-2006
 */
public class Java13TrustManagerWrapper implements X509TrustManager
{

	private final X509TrustManager trustManager;
	private final TrustChain trustChain;
	private final SSL ssl;

	public Java13TrustManagerWrapper( X509TrustManager m, TrustChain tc, SSL h )
	{
		this.trustManager = m;
		this.trustChain = tc;
		this.ssl = h;
	}

	public boolean isClientTrusted( X509Certificate[] chain )
	{
		ssl.setCurrentClientChain( chain );
		boolean firstTest = trustManager.isClientTrusted( chain );
		return test( firstTest, chain );
	}

	public boolean isServerTrusted( X509Certificate[] chain )
	{
		ssl.setCurrentServerChain( chain );
		boolean firstTest = trustManager.isServerTrusted( chain );
		return test( firstTest, chain );
	}

	public X509Certificate[] getAcceptedIssuers()
	{
		return trustManager.getAcceptedIssuers();
	}

	private boolean test( boolean firstTest, X509Certificate[] chain )
	{
		// Even if the first test failed, we might still be okay as long as
		// this SSLServer or SSLClient is setup to trust all certificates.
		if ( !firstTest )
		{
			if ( !trustChain.contains( TrustMaterial.TRUST_ALL ) )
			{
				return false;
			}
		}

		try
		{
			for ( int i = 0; i < chain.length; i++ )
			{
				X509Certificate c = chain[ i ];
				if ( ssl.getCheckExpiry() )
				{
					c.checkValidity();
				}
				if ( ssl.getCheckCRL() )
				{
					Certificates.checkCRL( c );
				}
			}
			return true;
		}
		catch ( CertificateException ce )
		{
			System.out.println( " FAILED!" );
			return false;
		}
	}

}
