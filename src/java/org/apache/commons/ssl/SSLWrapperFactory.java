package org.apache.commons.ssl;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.IOException;

/**
 * @author Julius Davies
 * @since 19-Sep-2006
 */
public interface SSLWrapperFactory
{

	public SSLSocket wrap( SSLSocket s ) throws IOException;

	public SSLServerSocket wrap( SSLServerSocket s ) throws IOException;

}
