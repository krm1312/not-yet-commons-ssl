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

package org.apache.commons.ssl;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Not thread-safe.  (But who would ever share this thing across multiple
 * threads???)
 *
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since May 1, 2006
 */
public class SSL
{
	private final static String[] KNOWN_PROTOCOLS =
			{ "TLSv1", "SSLv3", "SSLv2", "SSLv2Hello" };

	// SUPPORTED_CIPHERS_ARRAY is initialized in the static constructor.
	private final static String[] SUPPORTED_CIPHERS;
	private final static String[] DEFAULT_CIPHERS;

	public final static SortedSet KNOWN_PROTOCOLS_SET;
	public final static SortedSet SUPPORTED_CIPHERS_SET;

	// RC4
	public final static String SSL_RSA_WITH_RC4_128_SHA = "SSL_RSA_WITH_RC4_128_SHA";

	// 3DES
	public final static String SSL_RSA_WITH_3DES_EDE_CBC_SHA = "SSL_RSA_WITH_3DES_EDE_CBC_SHA";
	public final static String SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA = "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA";
	public final static String SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA = "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA";

	// AES-128
	public final static String TLS_RSA_WITH_AES_128_CBC_SHA = "TLS_RSA_WITH_AES_128_CBC_SHA";
	public final static String TLS_DHE_RSA_WITH_AES_128_CBC_SHA = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA";
	public final static String TLS_DHE_DSS_WITH_AES_128_CBC_SHA = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA";

	// AES-256
	public final static String TLS_RSA_WITH_AES_256_CBC_SHA = "TLS_RSA_WITH_AES_256_CBC_SHA";
	public final static String TLS_DHE_RSA_WITH_AES_256_CBC_SHA = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA";
	public final static String TLS_DHE_DSS_WITH_AES_256_CBC_SHA = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA";

	static
	{
		TreeSet ts = new TreeSet( Collections.reverseOrder() );
		ts.addAll( Arrays.asList( KNOWN_PROTOCOLS ) );
		KNOWN_PROTOCOLS_SET = Collections.unmodifiableSortedSet( ts );

		// SSLSocketFactory.getDefault() sometimes blocks on FileInputStream
		// reads of "/dev/random" (Linux only?).  You might find you system
		// stuck here.  Move the mouse around a little!
		SSLSocketFactory s = (SSLSocketFactory) SSLSocketFactory.getDefault();
		ts = new TreeSet();
		SUPPORTED_CIPHERS = s.getSupportedCipherSuites();
		DEFAULT_CIPHERS = s.getDefaultCipherSuites();
		Arrays.sort( SUPPORTED_CIPHERS );
		Arrays.sort( DEFAULT_CIPHERS );
		ts.addAll( Arrays.asList( SUPPORTED_CIPHERS ) );
		SUPPORTED_CIPHERS_SET = Collections.unmodifiableSortedSet( ts );
	}

	private Object sslContext = null;
	private int initCount = 0;
	private SSLSocketFactory socketFactory = null;
	private SSLServerSocketFactory serverSocketFactory = null;
	private HostnameVerifier hostnameVerifier = HostnameVerifier.DEFAULT;
	private boolean checkHostname = true;
	private final ArrayList allowedNames = new ArrayList();
	private boolean checkCRL = true;
	private boolean checkExpiry = true;
	private boolean useClientMode = false;
	private boolean useClientModeDefault = true;
	private int soTimeout = 24 * 60 * 60 * 1000; // default: one day
	private int connectTimeout = 60 * 60 * 1000; // default: one hour
	private TrustChain trustChain = null;
	private KeyMaterial keyMaterial = null;
	private String[] enabledCiphers = null;
	private String[] enabledProtocols = null;
	private String defaultProtocol = "TLS";
	private X509Certificate[] currentServerChain;
	private X509Certificate[] currentClientChain;
	private boolean wantClientAuth = true;
	private boolean needClientAuth = false;
	private SSLWrapperFactory sslWrapperFactory = SSLWrapperFactory.NO_WRAP;

	protected final boolean usingSystemProperties;

	public SSL()
			throws GeneralSecurityException, IOException
	{
		boolean usingSysProps = false;
		Properties props = System.getProperties();
		boolean ksSet = props.containsKey( "javax.net.ssl.keyStore" );
		boolean tsSet = props.containsKey( "javax.net.ssl.trustStore" );
		if ( ksSet )
		{
			String path = System.getProperty( "javax.net.ssl.keyStore" );
			String pwd = System.getProperty( "javax.net.ssl.keyStorePassword" );
			pwd = pwd != null ? pwd : ""; // JSSE default is "".
			File f = new File( path );
			if ( f.exists() )
			{
				KeyMaterial km = new KeyMaterial( path, pwd.toCharArray() );
				setKeyMaterial( km );
				usingSysProps = true;
			}
		}
		boolean trustMaterialSet = false;
		if ( tsSet )
		{
			String path = System.getProperty( "javax.net.ssl.trustStore" );
			String pwd = System.getProperty( "javax.net.ssl.trustStorePassword" );
			boolean pwdWasNull = pwd == null;
			pwd = pwdWasNull ? "" : pwd; // JSSE default is "".			
			File f = new File( path );
			if ( f.exists() )
			{
				TrustMaterial tm;
				try
				{
					tm = new TrustMaterial( path, pwd.toCharArray() );
				}
				catch ( GeneralSecurityException gse )
				{
					// Probably a bad password.  If we're using the default password,
					// let's try and survive this setback.
					if ( pwdWasNull )
					{
						tm = new TrustMaterial( path );
					}
					else
					{
						throw gse;
					}
				}

				setTrustMaterial( tm );
				usingSysProps = true;
				trustMaterialSet = true;
			}
		}

		/*
		  No default trust material was set.  We'll use the JSSE standard way
		  where we test for "JSSE_CACERTS" first, and then fall back on
		  "CACERTS".  We could just leave TrustMaterial null, but then our
		  setCheckCRL() and setCheckExpiry() features won't work.  We need a
		  non-null TrustMaterial object in order to intercept and decorate
		  the JVM's default TrustManager.
		*/
		if ( !trustMaterialSet )
		{
			setTrustMaterial( TrustMaterial.DEFAULT );
		}
		this.usingSystemProperties = usingSysProps;

		// By default we only use the strong ciphers (128 bit and higher).
		// Consumers can call "useDefaultJavaCiphers()" to get the 40 and 56 bit
		// ciphers back that Java normally has turned on.
		useStrongCiphers();
		dirtyAndReloadIfYoung();
	}

	private void dirty()
	{
		this.sslContext = null;
		this.socketFactory = null;
		this.serverSocketFactory = null;
	}

	private void dirtyAndReloadIfYoung()
			throws NoSuchAlgorithmException, KeyStoreException,
			       KeyManagementException, IOException, CertificateException
	{
		dirty();
		if ( initCount >= 0 && initCount <= 5 )
		{
			// The first five init's we do early (before any sockets are
			// created) in the hope that will trigger any explosions nice
			// and early, with the correct exception type.

			// After the first five init's, we revert to a regular
			// dirty / init pattern, and the "init" happens very late:
			// just before the socket is created.  If badness happens, a
			// wrapping RuntimeException will be thrown.
			init();
		}
	}

	public SSLContext getSSLContext()
			throws GeneralSecurityException, IOException

	{
		Object obj = getSSLContextAsObject();
		if ( JavaImpl.isJava13() )
		{
			try
			{
				return (SSLContext) obj;
			}
			catch ( ClassCastException cce )
			{
				throw new ClassCastException( "When using Java13 SSL, you must call SSL.getSSLContextAsObject() - " + cce );
			}
		}
		return (SSLContext) obj;
	}

	/**
	 * @return com.sun.net.ssl.SSLContext or javax.net.ssl.SSLContext depending
	 *         on the JSSE implementation we're using.
	 * @throws GeneralSecurityException problem creating SSLContext
	 * @throws IOException              problem creating SSLContext
	 */
	public Object getSSLContextAsObject()
			throws GeneralSecurityException, IOException

	{
		if ( sslContext == null )
		{
			init();
		}
		return sslContext;
	}

	public void addTrustMaterial( TrustChain trustChain )
			throws NoSuchAlgorithmException, KeyStoreException,
			       KeyManagementException, IOException, CertificateException
	{
		if ( this.trustChain == null || trustChain == TrustMaterial.TRUST_ALL )
		{
			this.trustChain = trustChain;
		}
		else
		{
			this.trustChain.addTrustMaterial( trustChain );
		}
		dirtyAndReloadIfYoung();
	}

	public void setTrustMaterial( TrustChain trustChain )
			throws NoSuchAlgorithmException, KeyStoreException,
			       KeyManagementException, IOException, CertificateException
	{
		this.trustChain = trustChain;
		dirtyAndReloadIfYoung();
	}

	public void setKeyMaterial( KeyMaterial keyMaterial )
			throws NoSuchAlgorithmException, KeyStoreException,
			       KeyManagementException, IOException, CertificateException
	{
		this.keyMaterial = keyMaterial;
		dirtyAndReloadIfYoung();
	}

	public X509Certificate[] getAssociatedCertificateChain()
	{
		if ( keyMaterial != null )
		{
			return keyMaterial.getAssociatedCertificateChain();
		}
		else
		{
			return null;
		}
	}

	public String[] getEnabledCiphers()
	{
		return enabledCiphers != null ? enabledCiphers : getDefaultCipherSuites();
	}

	public void useDefaultJavaCiphers()
	{
		String[] enabled = getEnabledCiphers();
		Arrays.sort( enabled );
		Arrays.sort( DEFAULT_CIPHERS );
		if ( !Arrays.equals( DEFAULT_CIPHERS, enabled ) )
		{
			setEnabledCiphers( DEFAULT_CIPHERS );
		}
	}

	public void useStrongCiphers()
	{
		LinkedList list = new LinkedList();
		addCipher( list, SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA, false );
		addCipher( list, SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA, false );
		addCipher( list, SSL_RSA_WITH_3DES_EDE_CBC_SHA, false );
		addCipher( list, SSL_RSA_WITH_RC4_128_SHA, false );
		addCipher( list, TLS_DHE_DSS_WITH_AES_128_CBC_SHA, false );
		addCipher( list, TLS_DHE_DSS_WITH_AES_256_CBC_SHA, false );
		addCipher( list, TLS_DHE_RSA_WITH_AES_128_CBC_SHA, false );
		addCipher( list, TLS_DHE_RSA_WITH_AES_256_CBC_SHA, false );
		addCipher( list, TLS_RSA_WITH_AES_128_CBC_SHA, false );
		addCipher( list, TLS_RSA_WITH_AES_256_CBC_SHA, false );
		String[] strongCiphers = new String[list.size()];
		list.toArray( strongCiphers );
		String[] currentCiphers = getEnabledCiphers();
		// Current ciphers must be default or something.  Odd that it's null,
		// though.
		if ( currentCiphers == null )
		{
			setEnabledCiphers( strongCiphers );
		}

		Arrays.sort( strongCiphers );
		Arrays.sort( currentCiphers );
		// Let's only call "setEnabledCiphers" if our array is actually different
		// than what's already set.
		if ( !Arrays.equals( strongCiphers, currentCiphers ) )
		{
			setEnabledCiphers( strongCiphers );
		}
	}

	public void setEnabledCiphers( String[] ciphers )
	{
		HashSet desired = new HashSet( Arrays.asList( ciphers ) );
		desired.removeAll( SUPPORTED_CIPHERS_SET );
		if ( !desired.isEmpty() )
		{
			throw new IllegalArgumentException( "following ciphers not supported: " + desired );
		}
		this.enabledCiphers = ciphers;
	}

	public String[] getEnabledProtocols()
	{
		return enabledProtocols != null ? enabledProtocols : KNOWN_PROTOCOLS;
	}

	public void setEnabledProtocols( String[] protocols )
	{
		HashSet desired = new HashSet( Arrays.asList( protocols ) );
		desired.removeAll( KNOWN_PROTOCOLS_SET );
		if ( !desired.isEmpty() )
		{
			throw new IllegalArgumentException( "following protocols not supported: " + desired );
		}
		this.enabledProtocols = protocols;
	}

	public String getDefaultProtocol()
	{
		return defaultProtocol;
	}

	public void setDefaultProtocol( String protocol )
	{
		this.defaultProtocol = protocol;
		dirty();
	}

	public boolean getCheckHostname()
	{
		return checkHostname;
	}

	/**
	 * @return String[] array of alternate "allowed names" to try against a
	 *         server's x509 CN field if the host/ip we used didn't match.
	 *         Returns an empty list if there are no "allowedNames" currently
	 *         set.
	 */
	public List getAllowedNames()
	{
		return Collections.unmodifiableList( allowedNames );
	}

	/**
	 * Offers a secure way to use virtual-hosting and SSL in some situations:
	 * for example you want to connect to "bar.com" but you know in advance
	 * that the SSL Certificate on that server only contains "CN=foo.com".  If
	 * you setAllowedNames( new String[] { "foo.com" } ) on your SSLClient in
	 * advance, you can connect securely, while still using "bar.com" as the
	 * host.
	 * <p/>
	 * Here's a code example using "cucbc.com" to connect, but anticipating
	 * "www.cucbc.com" in the server's certificate:
	 * <pre>
	 * SSLClient client = new SSLClient();
	 * client.setAllowedNames( new String[] { "www.cucbc.com" } );
	 * Socket s = client.createSocket( "cucbc.com", 443 );
	 * </pre>
	 * <p/>
	 * This technique is also useful if you don't want to use DNS, and want to
	 * connect using the IP address.
	 *
	 * @param allowedNames Collection of alternate "allowed names" to try against
	 *                     a server's x509 CN field if the host/ip we used didn't
	 *                     match.  Set to null to force strict matching against
	 *                     host/ip passed into createSocket().  Null is the
	 *                     default value.  Must be set in advance, before
	 *                     createSocket() is called.
	 */
	public void addAllowedNames( Collection allowedNames )
	{
		this.allowedNames.addAll( allowedNames );
	}

	public void addAllowedName( String allowedName )
	{
		this.allowedNames.add( allowedName );
	}

	public void clearAllowedNames()
	{
		this.allowedNames.clear();
	}

	public void setCheckHostname( boolean checkHostname )
	{
		this.checkHostname = checkHostname;
	}

	public void setHostnameVerifier( HostnameVerifier verifier )
	{
		if ( verifier == null )
		{
			verifier = HostnameVerifier.DEFAULT;
		}
		this.hostnameVerifier = verifier;
	}

	public HostnameVerifier getHostnameVerifier()
	{
		return hostnameVerifier;
	}

	public boolean getCheckCRL()
	{
		return checkCRL;
	}

	public void setCheckCRL( boolean checkCRL )
	{
		this.checkCRL = checkCRL;
	}

	public boolean getCheckExpiry()
	{
		return checkExpiry;
	}

	public void setCheckExpiry( boolean checkExpiry )
	{
		this.checkExpiry = checkExpiry;
	}

	public void setSoTimeout( int soTimeout )
	{
		if ( soTimeout < 0 )
		{
			throw new IllegalArgumentException( "soTimeout must not be negative" );
		}
		this.soTimeout = soTimeout;
	}

	public int getSoTimeout()
	{
		return soTimeout;
	}

	public void setConnectTimeout( int connectTimeout )
	{
		if ( connectTimeout < 0 )
		{
			throw new IllegalArgumentException( "connectTimeout must not be negative" );
		}
		this.connectTimeout = connectTimeout;
	}

	public void setUseClientMode( boolean useClientMode )
	{
		this.useClientModeDefault = false;
		this.useClientMode = useClientMode;
	}

	public boolean getUseClientModeDefault()
	{
		return useClientModeDefault;
	}

	public boolean getUseClientMode()
	{
		return useClientMode;
	}

	public void setWantClientAuth( boolean wantClientAuth )
	{
		this.wantClientAuth = wantClientAuth;
	}

	public void setNeedClientAuth( boolean needClientAuth )
	{
		this.needClientAuth = needClientAuth;
	}

	public boolean getWantClientAuth()
	{
		return wantClientAuth;
	}

	public boolean getNeedClientAuth()
	{
		return needClientAuth;
	}

	public SSLWrapperFactory getSSLWrapperFactory()
	{
		return this.sslWrapperFactory;
	}

	public void setSSLWrapperFactory( SSLWrapperFactory wf )
	{
		this.sslWrapperFactory = wf;
	}

	private void initThrowRuntime()
	{
		try
		{
			init();
		}
		catch ( GeneralSecurityException gse )
		{
			throw JavaImpl.newRuntimeException( gse );
		}
		catch ( IOException ioe )
		{
			throw JavaImpl.newRuntimeException( ioe );
		}
	}

	private void init()
			throws NoSuchAlgorithmException, KeyStoreException,
			       KeyManagementException, IOException, CertificateException
	{
		socketFactory = null;
		serverSocketFactory = null;
		this.sslContext = JavaImpl.init( this, trustChain, keyMaterial );
		initCount++;
	}

	public void doPreConnectSocketStuff( SSLSocket s )
			throws IOException
	{
		if ( !useClientModeDefault )
		{
			s.setUseClientMode( useClientMode );
		}
		if ( soTimeout > 0 )
		{
			s.setSoTimeout( soTimeout );
		}
		if ( enabledProtocols != null )
		{
			JavaImpl.setEnabledProtocols( s, enabledProtocols );
		}
		if ( enabledCiphers != null )
		{
			s.setEnabledCipherSuites( enabledCiphers );
		}
	}

	public void doPostConnectSocketStuff( SSLSocket s, String host )
			throws IOException
	{
		if ( checkHostname )
		{
			int size = allowedNames.size() + 1;
			String[] hosts = new String[size];
			// hosts[ 0 ] MUST ALWAYS be the host given to createSocket().			
			hosts[ 0 ] = host;
			int i = 1;
			for ( Iterator it = allowedNames.iterator(); it.hasNext(); i++ )
			{
				hosts[ i ] = (String) it.next();
			}
			hostnameVerifier.check( hosts, s );
		}
	}

	public SSLSocket createSocket() throws IOException
	{
		return sslWrapperFactory.wrap( JavaImpl.createSocket( this ) );
	}

	/**
	 * Attempts to get a new socket connection to the given host within the
	 * given time limit.
	 *
	 * @param remoteHost the host name/IP
	 * @param remotePort the port on the host
	 * @param localHost  the local host name/IP to bind the socket to
	 * @param localPort  the port on the local machine
	 * @param timeout    the connection timeout (0==infinite)
	 * @return Socket a new socket
	 * @throws IOException          if an I/O error occurs while creating the socket
	 * @throws UnknownHostException if the IP address of the host cannot be
	 *                              determined
	 */
	public Socket createSocket( String remoteHost, int remotePort,
	                            InetAddress localHost, int localPort,
	                            int timeout )
			throws IOException
	{
		// Only use our factory-wide connectTimeout if this method was passed
		// in a timeout of 0 (infinite).
		int factoryTimeout = getConnectTimeout();
		int connectTimeout = timeout == 0 ? factoryTimeout : timeout;
		SSLSocket s = JavaImpl.createSocket( this, remoteHost, remotePort,
		                                     localHost, localPort,
		                                     connectTimeout );
		return sslWrapperFactory.wrap( s );
	}

	public Socket createSocket( Socket s, String remoteHost, int remotePort,
	                            boolean autoClose )
			throws IOException
	{
		SSLSocketFactory sf = getSSLSocketFactory();
		s = sf.createSocket( s, remoteHost, remotePort, autoClose );
		doPreConnectSocketStuff( (SSLSocket) s );
		doPostConnectSocketStuff( (SSLSocket) s, remoteHost );
		return sslWrapperFactory.wrap( (SSLSocket) s );
	}

	public ServerSocket createServerSocket() throws IOException
	{
		SSLServerSocket ss = JavaImpl.createServerSocket( this );
		return getSSLWrapperFactory().wrap( ss, this );
	}

	/**
	 * Attempts to get a new socket connection to the given host within the
	 * given time limit.
	 *
	 * @param localHost the local host name/IP to bind against (null == ANY)
	 * @param port      the port to listen on
	 * @param backlog   number of connections allowed to queue up for accept().
	 * @return SSLServerSocket a new server socket
	 * @throws IOException if an I/O error occurs while creating thesocket
	 */
	public ServerSocket createServerSocket( int port, int backlog,
	                                        InetAddress localHost )
			throws IOException
	{
		SSLServerSocketFactory f = getSSLServerSocketFactory();
		ServerSocket ss = f.createServerSocket( port, backlog, localHost );
		SSLServerSocket s = (SSLServerSocket) ss;
		doPreConnectServerSocketStuff( s );
		return getSSLWrapperFactory().wrap( s, this );
	}

	public void doPreConnectServerSocketStuff( SSLServerSocket s )
			throws IOException
	{
		if ( soTimeout > 0 )
		{
			s.setSoTimeout( soTimeout );
		}
		if ( enabledProtocols != null )
		{
			JavaImpl.setEnabledProtocols( s, enabledProtocols );
		}
		if ( enabledCiphers != null )
		{
			s.setEnabledCipherSuites( enabledCiphers );
		}

		/*
		setNeedClientAuth( false ) has an annoying side effect:  it seems to
		reset setWantClient( true ) back to to false.  So I do things this
		way to make sure setting things "true" happens after setting things
		"false" - giving "true" priority.
		*/
		if ( !wantClientAuth )
		{
			JavaImpl.setWantClientAuth( s, wantClientAuth );
		}
		if ( !needClientAuth )
		{
			s.setNeedClientAuth( needClientAuth );
		}
		if ( wantClientAuth )
		{
			JavaImpl.setWantClientAuth( s, wantClientAuth );
		}
		if ( needClientAuth )
		{
			s.setNeedClientAuth( needClientAuth );
		}
	}

	public SSLSocketFactory getSSLSocketFactory()
	{
		if ( sslContext == null )
		{
			initThrowRuntime();
		}
		if ( socketFactory == null )
		{
			socketFactory = JavaImpl.getSSLSocketFactory( sslContext );
		}
		return socketFactory;
	}

	public SSLServerSocketFactory getSSLServerSocketFactory()
	{
		if ( sslContext == null )
		{
			initThrowRuntime();
		}
		if ( serverSocketFactory == null )
		{
			serverSocketFactory = JavaImpl.getSSLServerSocketFactory( sslContext );
		}
		return serverSocketFactory;
	}

	public int getConnectTimeout()
	{
		return connectTimeout;
	}

	public String[] getDefaultCipherSuites()
	{
		return getSSLSocketFactory().getDefaultCipherSuites();
	}

	public String[] getSupportedCipherSuites()
	{
		String[] s = new String[SUPPORTED_CIPHERS.length];
		System.arraycopy( SUPPORTED_CIPHERS, 0, s, 0, s.length );
		return s;
	}

	public TrustChain getTrustChain()
	{
		return trustChain;
	}

	public void setCurrentServerChain( X509Certificate[] chain )
	{
		this.currentServerChain = chain;
	}

	public void setCurrentClientChain( X509Certificate[] chain )
	{
		this.currentClientChain = chain;
	}

	public X509Certificate[] getCurrentServerChain()
	{
		return currentServerChain;
	}

	public X509Certificate[] getCurrentClientChain()
	{
		return currentClientChain;
	}

	public static void main( String[] args )
	{
		for ( int i = 0; i < SUPPORTED_CIPHERS.length; i++ )
		{
			System.out.println( SUPPORTED_CIPHERS[ i ] );
		}
		System.out.println();
		System.out.println( "----------------------------------------------" );
		addCipher( null, SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA, true );
		addCipher( null, SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA, true );
		addCipher( null, SSL_RSA_WITH_3DES_EDE_CBC_SHA, true );
		addCipher( null, SSL_RSA_WITH_RC4_128_SHA, true );
		addCipher( null, TLS_DHE_DSS_WITH_AES_128_CBC_SHA, true );
		addCipher( null, TLS_DHE_DSS_WITH_AES_256_CBC_SHA, true );
		addCipher( null, TLS_DHE_RSA_WITH_AES_128_CBC_SHA, true );
		addCipher( null, TLS_DHE_RSA_WITH_AES_256_CBC_SHA, true );
		addCipher( null, TLS_RSA_WITH_AES_128_CBC_SHA, true );
		addCipher( null, TLS_RSA_WITH_AES_256_CBC_SHA, true );
	}

	private static void addCipher( List l, String c, boolean printOnStandardOut )
	{
		boolean supported = false;
		if ( c != null && SUPPORTED_CIPHERS_SET.contains( c ) )
		{
			if ( l != null )
			{
				l.add( c );
			}
			supported = true;
		}
		if ( printOnStandardOut )
		{
			System.out.println( c + ":\t" + supported );
		}
	}


}
