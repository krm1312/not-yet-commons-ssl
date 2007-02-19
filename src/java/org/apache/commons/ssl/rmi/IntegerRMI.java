package org.apache.commons.ssl.rmi;

import java.io.Serializable;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

/**
 * @author Julius Davies
 * @since 18-Feb-2007
 */
public class IntegerRMI extends UnicastRemoteObject
		implements Remote, Serializable, RemoteInteger
{
	private int i;

	public IntegerRMI() throws RemoteException
	{
		super();
		this.i = (int) Math.round( Math.random() * 1000000.0 );
	}

	public int getInt() throws RemoteException
	{
		return i;
	}

	public boolean equals( Object o )
	{
		RemoteInteger ri = (RemoteInteger) o;
		try
		{
			return i == ri.getInt();
		}
		catch ( RemoteException re )
		{
			return false;
		}
	}


}
