package org.apache.commons.ssl;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLServerSocket;
import java.io.IOException;

/**
 * @author Julius Davies
 * @since 19-Sep-2006
 */
public class DefaultSSLWrapperFactory implements SSLWrapperFactory
{
	private final static DefaultSSLWrapperFactory instance =
	      new DefaultSSLWrapperFactory();

	private DefaultSSLWrapperFactory() {}

	public static DefaultSSLWrapperFactory getInstance() { return instance; }


	public SSLSocket wrap( SSLSocket s )
	{
		return new SSLSocketWrapper( s );
	}

	public SSLServerSocket wrap( SSLServerSocket s ) throws IOException
	{
		return new SSLServerSocketWrapper( s, this );
	}


}
