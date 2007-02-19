package org.apache.commons.ssl.rmi;

import java.rmi.Remote;
import java.rmi.RemoteException;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 22-Apr-2005
 */
public interface RemoteInteger extends Remote
{
	public int getInt() throws RemoteException;
}
