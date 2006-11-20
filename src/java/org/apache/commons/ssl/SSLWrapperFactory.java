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

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.IOException;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 19-Sep-2006
 */
public interface SSLWrapperFactory
{

	/**
	 * Wraps an SSLSSocket.
	 * @param s  SSLSocket to wrap.
	 * @return The new wrapped SSLSocket.
	 * @throws IOException if wrapping failed
	 */
	public SSLSocket wrap( SSLSocket s ) throws IOException;

	/**
	 * Wraps an SSLServerSocket. 
	 *
	 * @param s The SSLServerSocket to wrap.
	 * @param server  The SSLServer object that created the SSLServerSocket.
	 *                This way some important commons-ssl config can be applied
	 *                to the returned socket.
	 * @return The new wrapped SSLServerSocket.
	 * @throws IOException if wrapping failed
	 */
	public SSLServerSocket wrap( SSLServerSocket s, SSLServer server )
			throws IOException;

}
