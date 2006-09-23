package org.apache.commons.ssl.rmi;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.Date;

/**
 * @author Julius Davies
 * @since 22-Apr-2005
 */
public interface RemoteDate extends Remote
{
	public Date getDate() throws RemoteException;
}
