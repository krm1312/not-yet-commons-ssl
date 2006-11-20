/*
 * $Header$
 * $Revision$
 * $Date$
 *
 * ====================================================================
 *
 *  Copyright 1999-2004 The Apache Software Foundation
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
 * [Additional notices, if required by prior licensing conditions]
 *
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU Lesser General Public License Version 2 or later
 * (the "LGPL"), in which case the provisions of the LGPL are 
 * applicable instead of those above.  See terms of LGPL at
 * <http://www.gnu.org/copyleft/lesser.txt>.
 * If you wish to allow use of your version of this file only under 
 * the terms of the LGPL and not to allow others to use your version
 * of this file under the Apache Software License, indicate your 
 * decision by deleting the provisions above and replace them with 
 * the notice and other provisions required by the LGPL.  If you do 
 * not delete the provisions above, a recipient may use your version 
 * of this file under either the Apache Software License or the LGPL.
 */

package org.apache.commons.httpclient.contrib.ssl;

import org.apache.commons.ssl.HttpSecureProtocol;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * A <code>SecureProtocolSocketFactory</code> that uses JSSE to create
 * SSL sockets.  It will also support host name verification to help preventing
 * man-in-the-middle attacks.  Host name verification is turned <b>on</b> by
 * default but one will be able to turn it off, which might be a useful feature
 * during development.  Host name verification will make sure the SSL sessions
 * server host name matches with the the host name returned in the
 * server certificates "Common Name" field of the "SubjectDN" entry.
 *
 * @author <a href="mailto:hauer@psicode.com">Sebastian Hauer</a>
 *         <p/>
 *         DISCLAIMER: HttpClient developers DO NOT actively support this component.
 *         The component is provided as a reference material, which may be inappropriate
 *         for use without additional customization.
 *         </p>
 */
public class StrictSSLProtocolSocketFactory extends HttpSecureProtocol
{

	/**
	 * Constructor for StrictSSLProtocolSocketFactory.
	 *
	 * @param verifyHostname The host name verification flag. If set to
	 *                       <code>true</code> the SSL sessions server host name will be compared
	 *                       to the host name returned in the server certificates "Common Name"
	 *                       field of the "SubjectDN" entry.  If these names do not match a
	 *                       Exception is thrown to indicate this.  Enabling host name verification
	 *                       will help to prevent from man-in-the-middle attacks.  If set to
	 *                       <code>false</code> host name verification is turned off.
	 *                       <p/>
	 *                       Code sample:
	 *                       <p/>
	 *                       <blockquote>
	 *                       Protocol stricthttps = new Protocol(
	 *                       "https", new StrictSSLProtocolSocketFactory(true), 443);
	 *                       <p/>
	 *                       HttpClient client = new HttpClient();
	 *                       client.getHostConfiguration().setHost("localhost", 443, stricthttps);
	 *                       </blockquote>
	 */
	public StrictSSLProtocolSocketFactory( boolean verifyHostname )
			throws GeneralSecurityException, IOException
	{
		super();
		super.setCheckHostname( verifyHostname );
	}

	/**
	 * Constructor for StrictSSLProtocolSocketFactory.
	 * Host name verification will be enabled by default.
	 */
	public StrictSSLProtocolSocketFactory()
			throws GeneralSecurityException, IOException
	{
		this( true );
	}

	/**
	 * Set the host name verification flag.
	 *
	 * @param verifyHostname The host name verification flag. If set to
	 *                       <code>true</code> the SSL sessions server host name will be compared
	 *                       to the host name returned in the server certificates "Common Name"
	 *                       field of the "SubjectDN" entry.  If these names do not match a
	 *                       Exception is thrown to indicate this.  Enabling host name verification
	 *                       will help to prevent from man-in-the-middle attacks.  If set to
	 *                       <code>false</code> host name verification is turned off.
	 */
	public void setHostnameVerification( boolean verifyHostname )
	{
		super.setCheckHostname( verifyHostname );
	}

	/**
	 * Gets the status of the host name verification flag.
	 *
	 * @return Host name verification flag.  Either <code>true</code> if host
	 *         name verification is turned on, or <code>false</code> if host name
	 *         verification is turned off.
	 */
	public boolean getHostnameVerification()
	{
		return super.getCheckHostname();
	}

}
