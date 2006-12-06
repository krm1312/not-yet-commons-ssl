package org.apache.commons.ssl;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * @author Julius Davies
 * @since 5-Dec-2006
 */
public class Base64InputStream extends FilterInputStream
{
	private final static byte[] LINE_ENDING =
			System.getProperty( "line.separator" ).getBytes();

	final boolean decodeMode;

	byte[] currentLine = null;
	int pos = 0;

	public Base64InputStream( InputStream base64, boolean decodeMode )
	{
		super( base64 );
		this.decodeMode = decodeMode;
	}

	public int read() throws IOException
	{
		getLine();
		if ( currentLine == null )
		{
			return -1;
		}
		else
		{
			byte b = currentLine[ pos++ ];
			if ( pos >= currentLine.length )
			{
				currentLine = null;
			}
			return b;
		}
	}

	public int read( byte b[], int off, int len ) throws IOException
	{
		if ( b == null )
		{
			throw new NullPointerException();
		}
		else if ( ( off < 0 ) || ( off > b.length ) || ( len < 0 ) ||
		          ( ( off + len ) > b.length ) || ( ( off + len ) < 0 ) )
		{
			throw new IndexOutOfBoundsException();
		}
		else if ( len == 0 )
		{
			return 0;
		}

		getLine();
		if ( currentLine == null )
		{
			return -1;
		}
		int size = Math.min( currentLine.length - pos, len );
		System.arraycopy( currentLine, pos, b, off, size );
		if ( size >= currentLine.length - pos )
		{
			currentLine = null;
		}
		else
		{
			pos += size;
		}
		return size;
	}

	private void getLine() throws IOException
	{
		if ( currentLine == null )
		{
			if ( decodeMode )
			{
				String line = Util.readLine( in );
				if ( line != null )
				{
					byte[] b = line.getBytes();
					currentLine = Base64.decodeBase64( b );
					pos = 0;
				}
			}
			else
			{
				// It will expand to 64 bytes (16 * 4) after base64 encoding!
				byte[] b = Util.streamToBytes( in, 16 * 3 );
				if ( b.length > 0 )
				{
					b = Base64.encodeBase64( b );

					int lfLen = LINE_ENDING.length;
					currentLine = new byte[b.length + lfLen];
					System.arraycopy( b, 0, currentLine, 0, b.length );
					System.arraycopy( LINE_ENDING, 0, currentLine, b.length, lfLen );
				}
			}
		}
	}


}
