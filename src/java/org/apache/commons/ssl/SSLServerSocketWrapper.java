package org.apache.commons.ssl;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.ServerSocketChannel;

/**
 * @author Julius Davies
 * @since 11-Sep-2006
 */
public class SSLServerSocketWrapper extends SSLServerSocket
{
	protected SSLServerSocket s;
	protected SSLWrapperFactory wf;

	public SSLServerSocketWrapper( SSLServerSocket s, SSLWrapperFactory wf )
	      throws IOException
	{
		super();
		this.s = s;
		this.wf = wf;
	}

	/* javax.net.ssl.SSLServerSocket */

	public String[]      getEnabledCipherSuites()                                { return s.getEnabledCipherSuites();   }
	public String[]      getEnabledProtocols()                                   { return s.getEnabledProtocols();      }
	public boolean       getEnableSessionCreation()                              { return s.getEnableSessionCreation(); }
	public boolean       getNeedClientAuth()                                     { return s.getNeedClientAuth();        }
	public String[]      getSupportedCipherSuites()                              { return s.getSupportedCipherSuites(); }
	public String[]      getSupportedProtocols()                                 { return s.getSupportedProtocols();    }
	public boolean       getUseClientMode()                                      { return s.getUseClientMode();         }
	public boolean       getWantClientAuth()                                     { return s.getWantClientAuth();        }
	public void          setEnabledCipherSuites( String[] suites )               { s.setEnabledCipherSuites( suites );  }
	public void          setEnabledProtocols( String[] protocols )               { s.setEnabledProtocols( protocols );  }
	public void          setEnableSessionCreation( boolean flag )                { s.setEnableSessionCreation( flag );  }
	public void          setNeedClientAuth( boolean need )                       { s.setNeedClientAuth( need );         }
	public void          setUseClientMode( boolean use )                         { s.setUseClientMode( use );           }
	public void          setWantClientAuth( boolean want )                       { s.setWantClientAuth( want );         }

	/* java.net.Socket */

	public void          bind(SocketAddress endpoint)     throws IOException     { s.bind( endpoint );                  }
	public void          bind(SocketAddress ep, int bl)   throws IOException     { s.bind( ep, bl );                    }
	public void          close()                          throws IOException     { s.close();                           }
	public ServerSocketChannel getChannel()                                      { return s.getChannel();               }
	public InetAddress   getInetAddress()                                        { return s.getInetAddress();           }
	public int           getLocalPort()                                          { return s.getLocalPort();             }
	public SocketAddress getLocalSocketAddress()                                 { return s.getLocalSocketAddress();    }
	public int           getReceiveBufferSize()           throws SocketException { return s.getReceiveBufferSize();     }
	public boolean       getReuseAddress()                throws SocketException { return s.getReuseAddress();          }
	public int           getSoTimeout()                   throws IOException     { return s.getSoTimeout();             }
	public boolean       isBound()                                               { return s.isBound();                  }
	public boolean       isClosed()                                              { return s.isClosed();                 }
	public void          setReceiveBufferSize(int size)   throws SocketException { s.setReceiveBufferSize( size );      }
	public void          setReuseAddress(boolean on)      throws SocketException { s.setReuseAddress( on );             }
	public void          setSoTimeout(int timeout)        throws SocketException { s.setSoTimeout( timeout );           }
	public String        toString()                                              { return s.toString();                 }

	public Socket accept() throws IOException
	{
		// System.out.println( "server-socket accept(): " + this );
		return wf.wrap( (SSLSocket) s.accept() );
	}


	/*  Java 1.5
	public void setPerformancePreferences(int connectionTime, int latency, int bandwidth)
	{
		s.setPerformancePreferences( connectionTime, latency, bandwidth );
	}
	*/




}
