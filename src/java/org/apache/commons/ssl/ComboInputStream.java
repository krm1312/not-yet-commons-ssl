package org.apache.commons.ssl;

import java.io.IOException;
import java.io.InputStream;

/**
 * @author Julius Davies
 * @since 5-Dec-2006
 */
public class ComboInputStream extends InputStream
{
	private boolean headDone;
	private InputStream head;
	private InputStream tail;

	public ComboInputStream( InputStream head, InputStream tail )
	{
		this.head = head != null ? head : tail;
		this.tail = tail != null ? tail : head;
	}

	public int read() throws IOException
	{
		int c;
		if ( headDone )
		{
			c = tail.read();
		}
		else
		{
			c = head.read();
			if ( c == -1 )
			{
				headDone = true;
				c = tail.read();
			}
		}
		return c;
	}

	public int available() throws IOException
	{
		return tail.available() + head.available();
	}

	public void close() throws IOException
	{
		try
		{
			head.close();
		}
		finally
		{
			if ( head != tail )
			{
				tail.close();
			}
		}
	}

	public int read( byte b[], int off, int len ) throws IOException
	{
		int c;
		if ( headDone )
		{
			c = tail.read( b, off, len );
		}
		else
		{
			c = head.read( b, off, len );
			if ( c == -1 )
			{
				headDone = true;
				c = tail.read( b, off, len );
			}
		}
		return c;
	}

}
