package org.apache.commons.ssl;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLProtocolException;
import javax.net.ssl.SSLSocket;
import java.io.EOFException;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.rmi.server.RMISocketFactory;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;


/**
 * @author Julius Davies
 * @since 22-Apr-2005
 */
public class RMISocketFactoryImpl extends RMISocketFactory
{
	public final static String LOCAL_INTERNET_FACING_ADDRESS;
	public final static String RMI_HOSTNAME_KEY = "java.rmi.server.hostname";
	private final static LogWrapper log = LogWrapper.getLogger( RMISocketFactoryImpl.class );

	static
	{
		String google = "216.239.39.99";
		String ip = null;
		try
		{
			DatagramSocket dg = new DatagramSocket();
			dg.setSoTimeout( 250 );
			// 216.239.39.99 is google.com
			// This code doesn't actually send any packets (so no firewalls can
			// get in the way).  It's just a neat trick for getting our
			// internet-facing interface card.
			InetAddress addr = InetAddress.getByName( google );
			dg.connect( addr, 12345 );
			ip = dg.getLocalAddress().getHostAddress();
			log.debug( "Using bogus UDP socket (" + google + ":12345), I think my IP address is: " + ip );
			dg.close();
			if ( "0.0.0.0".equals( ip ) )
			{
				ip = null;
			}
		}
		catch ( IOException ioe )
		{
			log.debug( "Bogus UDP didn't work: " + ioe );
		}
		finally
		{
			LOCAL_INTERNET_FACING_ADDRESS = ip;
		}
	}

	private volatile String localBindingAddress;
	private volatile SocketFactory defaultClient;
	private volatile ServerSocketFactory sslServer;
	private Map clientMap = new TreeMap();
	private Map serverSockets = new HashMap();
	private final SocketFactory plainClient = SocketFactory.getDefault();

	public RMISocketFactoryImpl() throws GeneralSecurityException, IOException
	{
		setServer( new SSLServer() );
		setDefaultClient( new SSLClient() );
	}

	public void setLocalBindingAddress( String ip )
	{
		this.localBindingAddress = ip;
	}

	public String getLocalBindingAddress() { return localBindingAddress; }

	public void setServer( ServerSocketFactory f )
	      throws GeneralSecurityException, IOException
	{
		this.sslServer = f;
		trustOurself();
	}

	public void setDefaultClient( SocketFactory f )
	      throws GeneralSecurityException, IOException
	{
		this.defaultClient = f;
		trustOurself();
	}

	public void setClient( String host, SocketFactory f )
	      throws GeneralSecurityException, IOException
	{
		if ( f != null && sslServer != null )
		{
			boolean clientIsCommonsSSL = f instanceof SSLClient;
			boolean serverIsCommonsSSL = sslServer instanceof SSLServer;
			if ( clientIsCommonsSSL && serverIsCommonsSSL )
			{
				SSLClient c = (SSLClient) f;
				SSLServer s = (SSLServer) sslServer;
				trustEachOther( c, s );
			}
		}
		Set names = hostnamePossibilities( host );
		Iterator it = names.iterator();
		synchronized ( this )
		{
			while ( it.hasNext() )
			{
				clientMap.put( (String) it.next(), f );
			}
		}
	}

	public void removeClient( String host )
	{
		Set names = hostnamePossibilities( host );
		Iterator it = names.iterator();
		synchronized ( this )
		{
			while ( it.hasNext() )
			{
				clientMap.remove( (String) it.next() );
			}
		}
	}

	public synchronized void removeClient( SocketFactory sf )
	{
		Iterator it = clientMap.entrySet().iterator();
		while ( it.hasNext() )
		{
			Map.Entry entry = (Map.Entry) it.next();
			Object o = entry.getValue();
			if ( sf.equals( o ) )
			{
				it.remove();
			}
		}
	}

	private Set hostnamePossibilities( String host )
	{
		host = host != null ? host.toLowerCase().trim() : "";
		if ( "".equals( host ) )
		{
			return Collections.EMPTY_SET;
		}
		TreeSet names = new TreeSet();
		names.add( host );
		InetAddress[] addresses = null;
		try
		{
			// If they gave us "hostname.com", this will give us the various
			// IP addresses:
			addresses = InetAddress.getAllByName( host );
			for ( int i = 0; i < addresses.length; i++ )
			{
				String name1 = addresses[ i ].getHostName();
				String name2 = addresses[ i ].getHostAddress();
				names.add( name1.trim().toLowerCase() );
				names.add( name2.trim().toLowerCase() );
			}
		}
		catch ( UnknownHostException uhe )
		{
		}

		try
		{
			host = InetAddress.getByName( host ).getHostAddress();

			// If they gave us "1.2.3.4", this will hopefully give us
			// "hostname.com" so that we can then try and find any other
			// IP addresses associated with that name.
			host = InetAddress.getByName( host ).getHostName();
			names.add( host.trim().toLowerCase() );
			addresses = InetAddress.getAllByName( host );
			for ( int i = 0; i < addresses.length; i++ )
			{
				String name1 = addresses[ i ].getHostName();
				String name2 = addresses[ i ].getHostAddress();
				names.add( name1.trim().toLowerCase() );
				names.add( name2.trim().toLowerCase() );
			}
		}
		catch ( UnknownHostException uhe )
		{
		}
		return names;
	}

	private void trustOurself()
	      throws GeneralSecurityException, IOException
	{
		if ( defaultClient == null || sslServer == null )
		{
			return;
		}
		boolean clientIsCommonsSSL = defaultClient instanceof SSLClient;
		boolean serverIsCommonsSSL = sslServer instanceof SSLServer;
		if ( clientIsCommonsSSL && serverIsCommonsSSL )
		{
			SSLClient c = (SSLClient) defaultClient;
			SSLServer s = (SSLServer) sslServer;
			trustEachOther( c, s );
		}
	}

	private void trustEachOther( SSLClient client, SSLServer server )
	      throws GeneralSecurityException, IOException
	{
		if ( client != null && server != null )
		{
			// Our own client should trust our own server.
			X509Certificate[] certs = server.getAssociatedCertificateChain();
			if ( certs != null && certs[ 0 ] != null )
			{
				TrustMaterial tm = new TrustMaterial( certs[ 0 ] );
				client.addTrustMaterial( tm );
			}

			// Our own server should trust our own client.
			certs = client.getAssociatedCertificateChain();
			if ( certs != null && certs[ 0 ] != null )
			{
				TrustMaterial tm = new TrustMaterial( certs[ 0 ] );
				server.addTrustMaterial( tm );
			}
		}
	}

	public ServerSocketFactory getServer() { return sslServer; }

	public SocketFactory getDefaultClient() { return defaultClient; }

	public synchronized SocketFactory getClient( String host )
	{
		host = host != null ? host.trim().toLowerCase() : "";
		SocketFactory sf = (SocketFactory) clientMap.get( host );
		return sf;
	}

	private void initLocalBindingAddress()
	{
		String systemRMIHostname = System.getProperty( RMI_HOSTNAME_KEY );
		if ( localBindingAddress == null )
		{
			localBindingAddress = systemRMIHostname;
			if ( localBindingAddress == null )
			{
				localBindingAddress = LOCAL_INTERNET_FACING_ADDRESS;
				// LOCAL_INTERNET_FACING_ADDRESS itself might be null.  In that
				// case we're going to bind client sockets to ANY.
			}
		}
		if ( systemRMIHostname == null && localBindingAddress != null )
		{
			System.setProperty( RMI_HOSTNAME_KEY, localBindingAddress );
		}
	}

	public synchronized ServerSocket createServerSocket( int port )
	      throws IOException
	{
		initLocalBindingAddress();

		// Re-use existing ServerSocket if possible.
		Integer key = new Integer( port );
		ServerSocket ss = (ServerSocket) serverSockets.get( key );
		if ( ss == null )
		{
			log.debug( "commons-ssl RMI server-socket: listening on port " + port );
			ss = sslServer.createServerSocket( port );
			serverSockets.put( key, ss );
		}
		return ss;
	}

	public Socket createSocket( String host, int port )
	      throws IOException
	{
		host = host != null ? host.trim().toLowerCase() : "";
		initLocalBindingAddress();
		InetAddress local = null;
		if ( localBindingAddress != null )
		{
			local = InetAddress.getByName( localBindingAddress );
		}

		SocketFactory sf = null;
		synchronized ( this )
		{
			sf = (SocketFactory) clientMap.get( host );
		}
		if ( sf == null )
		{
			sf = defaultClient;
		}

		Socket s = null;
		SSLSocket ssl = null;
		int soTimeout = Integer.MIN_VALUE;
		IOException reasonForPlainSocket = null;
		boolean tryPlain = false;
		try
		{
			s = sf.createSocket( host, port, local, 0 );
			soTimeout = s.getSoTimeout();
			if ( !( s instanceof SSLSocket ) )
			{
				return s;
			}
			else
			{
				ssl = (SSLSocket) s;
			}

			// If we don't get the peer certs in 15 seconds, revert to plain
			// socket.
			ssl.setSoTimeout( 15000 );
			ssl.getSession().getPeerCertificates();

			// Everything worked out okay, so go back to original soTimeout.
			ssl.setSoTimeout( soTimeout );
			return ssl;
		}
		catch ( IOException ioe )
		{
			// SSL didn't work.  Let's analyze the IOException to see if maybe
			// we're accidentally attempting to talk to a plain-socket RMI
			// server.
			Throwable t = ioe;
			while ( !tryPlain && t != null )
			{
				tryPlain = tryPlain || t instanceof EOFException;
				tryPlain = tryPlain || t instanceof SocketTimeoutException;
				tryPlain = tryPlain || t instanceof SSLProtocolException;
				t = t.getCause();
			}
			if ( !tryPlain && ioe instanceof SSLPeerUnverifiedException )
			{
				try
				{
					ssl.startHandshake();
				}
				catch ( IOException ioe2 )
				{
					// Stacktrace from startHandshake() will be more descriptive
					// then the one we got from getPeerCertificates().
					ioe = ioe2;
					t = ioe2;
					while ( !tryPlain && t != null )
					{
						tryPlain = tryPlain || t instanceof EOFException;
						tryPlain = tryPlain || t instanceof SocketTimeoutException;
						tryPlain = tryPlain || t instanceof SSLProtocolException;
						t = t.getCause();
					}
				}
			}
			if ( !tryPlain )
			{
				throw ioe;
			}
			else
			{
				reasonForPlainSocket = ioe;
			}
		}
		finally
		{
			// Some debug logging:
			boolean isPlain = tryPlain || ssl == null;
			String socket = isPlain ? "RMI plain-socket " : "RMI ssl-socket ";
			String localIP = local != null ? local.getHostAddress() : "ANY";
			StringBuffer buf = new StringBuffer( 64 );
			buf.append( socket );
			buf.append( localIP );
			buf.append( " --> " );
			buf.append( host );
			buf.append( ":" );
			buf.append( port );
			log.debug( buf.toString() );
		}

		// SSL didn't work.  Remote server either timed out, or sent EOF, or
		// there was some kind of SSLProtocolException.  (Any other problem
		// would have caused an IOException to be thrown, so execution wouldn't
		// have made it this far).  Maybe plain socket will work in these three
		// cases.
		sf = plainClient;
		s = JavaImpl.connect( null, sf, host, port, local, 0, 15000 );
		if ( soTimeout != Integer.MIN_VALUE )
		{
			s.setSoTimeout( soTimeout );
		}

		try
		{
			setClient( host, plainClient );
			String msg = "RMI downgrading from SSL to plain-socket for " + host + " because of " + reasonForPlainSocket;
			log.warn( msg, reasonForPlainSocket );
		}
		catch ( GeneralSecurityException gse )
		{
			throw new RuntimeException( "can't happen because we're using plain socket", gse );
			// won't happen because we're using plain socket, not SSL.
		}

		return s;
	}

}
