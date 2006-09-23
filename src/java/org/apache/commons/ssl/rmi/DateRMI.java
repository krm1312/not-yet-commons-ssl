package org.apache.commons.ssl.rmi;

import java.io.Serializable;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.util.Date;

/**
 * @author Julius Davies
 * @since Jul 5, 2004
 */
public class DateRMI extends UnicastRemoteObject
      implements Remote, Serializable, RemoteDate
{
	// private final static Logger log = Logger.getLogger( DateRMI.class );

	private Date d;

	public DateRMI() throws RemoteException
	{
		super();
		this.d = new Date();
	}

	public Date getDate() throws RemoteException
	{
		return d;
	}

	public boolean equals( Object o )
	{
		RemoteDate rd = (RemoteDate) o;
		try
		{
			return d.equals( rd.getDate() );
		}
		catch ( RemoteException re )
		{
//			log.warn( re.toString(), re );
			return false;
		}
	}

}
