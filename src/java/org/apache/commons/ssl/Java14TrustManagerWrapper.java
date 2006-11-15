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

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 30-Mar-2006
 */
public class Java14TrustManagerWrapper implements X509TrustManager
{
	private final X509TrustManager trustManager;
	private final TrustChain trustChain;
	private final SSL ssl;

	public Java14TrustManagerWrapper( X509TrustManager m, TrustChain tc, SSL h )
	{
		this.trustManager = m;
		this.trustChain = tc;
		this.ssl = h;
	}

	public void checkClientTrusted( X509Certificate[] chain, String authType )
			throws CertificateException
	{
		ssl.setCurrentClientChain( chain );
		if ( trustChain.contains( TrustMaterial.TRUST_ALL ) )
		{
			return;
		}
		trustManager.checkClientTrusted( chain, authType );
	}

	public void checkServerTrusted( X509Certificate[] chain, String authType )
			throws CertificateException
	{
		ssl.setCurrentServerChain( chain );
		if ( trustChain.contains( TrustMaterial.TRUST_ALL ) )
		{
			return;
		}
		trustManager.checkServerTrusted( chain, authType );
	}

	public X509Certificate[] getAcceptedIssuers()
	{
		return trustManager.getAcceptedIssuers();
	}

}
