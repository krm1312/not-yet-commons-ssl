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

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.SocketChannel;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 16-Aug-2006
 */
public class SSLSocketWrapper extends SSLSocket
{
	protected SSLSocket s;

	public SSLSocketWrapper( SSLSocket s )
	{
		this.s = s;
		// System.out.println( "SSLSocketWrapper new! " + this );
	}

	/* javax.net.ssl.SSLSocket */

	public void addHandshakeCompletedListener( HandshakeCompletedListener hcl )
	{
		s.addHandshakeCompletedListener( hcl );
	}

	public void removeHandshakeCompletedListener( HandshakeCompletedListener hcl )
	{
		s.removeHandshakeCompletedListener( hcl );
	}

	public String[] getSupportedCipherSuites()
	{
		return s.getSupportedCipherSuites();
	}

	public boolean getEnableSessionCreation()
	{
		return s.getEnableSessionCreation();
	}

	public String[] getEnabledCipherSuites()
	{
		return s.getEnabledCipherSuites();
	}

	public String[] getSupportedProtocols() { return s.getSupportedProtocols(); }

	public String[] getEnabledProtocols() { return s.getEnabledProtocols(); }

	public SSLSession getSession() { return s.getSession(); }

	public boolean getUseClientMode() { return s.getUseClientMode(); }

	public boolean getNeedClientAuth() { return s.getNeedClientAuth(); }

	public boolean getWantClientAuth() { return s.getWantClientAuth(); }

	public void setEnabledCipherSuites( String[] cs )
	{
		s.setEnabledCipherSuites( cs );
	}

	public void setEnabledProtocols( String[] ep )
	{
		s.setEnabledProtocols( ep );
	}

	public void startHandshake() throws IOException { s.startHandshake(); }

	public void setUseClientMode( boolean b ) { s.setUseClientMode( b ); }

	public void setNeedClientAuth( boolean b ) { s.setNeedClientAuth( b ); }

	public void setWantClientAuth( boolean b ) { s.setWantClientAuth( b ); }

	public void setEnableSessionCreation( boolean b )
	{
		s.setEnableSessionCreation( b );
	}

	/* java.net.Socket */

	public SocketChannel getChannel() { return s.getChannel(); }

	public InetAddress getInetAddress() { return s.getInetAddress(); }

	public boolean getKeepAlive() throws SocketException
	{
		return s.getKeepAlive();
	}

	public InetAddress getLocalAddress() { return s.getLocalAddress(); }

	public int getLocalPort() { return s.getLocalPort(); }

	public SocketAddress getLocalSocketAddress()
	{
		return s.getLocalSocketAddress();
	}

	public boolean getOOBInline() throws SocketException
	{
		return s.getOOBInline();
	}

	public int getPort() { return s.getPort(); }

	public int getReceiveBufferSize() throws SocketException
	{
		return s.getReceiveBufferSize();
	}

	public SocketAddress getRemoteSocketAddress()
	{
		return s.getRemoteSocketAddress();
	}

	public boolean getReuseAddress() throws SocketException
	{
		return s.getReuseAddress();
	}

	public int getSendBufferSize() throws SocketException
	{
		return s.getSendBufferSize();
	}

	public int getSoLinger() throws SocketException { return s.getSoLinger(); }

	public int getSoTimeout() throws SocketException { return s.getSoTimeout(); }

	public boolean getTcpNoDelay() throws SocketException
	{
		return s.getTcpNoDelay();
	}

	public int getTrafficClass() throws SocketException
	{
		return s.getTrafficClass();
	}

	public boolean isBound() { return s.isBound(); }

	public boolean isClosed() { return s.isClosed(); }

	public boolean isConnected() { return s.isConnected(); }

	public boolean isInputShutdown() { return s.isInputShutdown(); }

	public boolean isOutputShutdown() { return s.isOutputShutdown(); }

	public void sendUrgentData( int data ) throws IOException
	{
		s.sendUrgentData( data );
	}

	public void setKeepAlive( boolean on ) throws SocketException
	{
		s.setKeepAlive( on );
	}

	public void setOOBInline( boolean on ) throws SocketException
	{
		s.setOOBInline( on );
	}

	public void setReceiveBufferSize( int size ) throws SocketException
	{
		s.setReceiveBufferSize( size );
	}

	public void setReuseAddress( boolean on ) throws SocketException
	{
		s.setReuseAddress( on );
	}

	public void setSendBufferSize( int size ) throws SocketException
	{
		s.setSendBufferSize( size );
	}

	public void setSoLinger( boolean on, int l ) throws SocketException
	{
		s.setSoLinger( on, l );
	}

	public void setSoTimeout( int timeout ) throws SocketException
	{
		s.setSoTimeout( timeout );
	}

	public void setTcpNoDelay( boolean on ) throws SocketException
	{
		s.setTcpNoDelay( on );
	}

	public void setTrafficClass( int tc ) throws SocketException
	{
		s.setTrafficClass( tc );
	}

	public void shutdownInput() throws IOException { s.shutdownInput(); }

	public void shutdownOutput() throws IOException { s.shutdownOutput(); }

	public String toString() { return s.toString(); }

	/*  Java 1.5
	public void setPerformancePreferences(int connectionTime, int latency, int bandwidth)
	{
		s.setPerformancePreferences( connectionTime, latency, bandwidth );
	}
	*/

	public void bind( SocketAddress bindpoint ) throws IOException
	{
		//System.out.println( "bind " + s );
		s.bind( bindpoint );
	}

	public void close() throws IOException
	{
		// System.out.println( "close " + s );
		s.close();
	}

	public void connect( SocketAddress endpoint ) throws IOException
	{
		// System.out.println( "connect " + s );
		s.connect( endpoint );
	}

	public void connect( SocketAddress endpoint, int timeout ) throws IOException
	{
		// System.out.println( "connect-timeout " + s );
		s.connect( endpoint, timeout );
	}

	public InputStream getInputStream() throws IOException
	{
		// System.out.println( "getInputStream " + s );
		return s.getInputStream();
	}

	public OutputStream getOutputStream() throws IOException
	{
		// System.out.println( "getOutputStream " + s );
		return s.getOutputStream();
	}

}
