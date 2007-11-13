package org.apache.commons.ssl;

import org.apache.commons.ssl.util.Hex;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Arrays;

/**
 * @author Julius Davies
 * @since 3-Jul-2007
 */
public class OpenSSLTest
{

	public static void main( String[] args ) throws Exception
	{
        String path = args[ 0 ];
		File f = new File( path );
		if ( f.isDirectory() )
		{
			File[] files = f.listFiles();
			Arrays.sort( files );
			for ( int i = 0; i < files.length; i++ )
			{
				process( files[ i ], 0 );
			}
		}
		else
		{
			System.out.println( "Attempting decrypt!" );

			String keyS = "1234567890ABDEF01234567890ABDEFF";
			String ivS = "1234567890ABDEF01234567890ABDEFF";
			byte[] key = Hex.decode( keyS.getBytes( ) );
			byte[] iv = Hex.decode( ivS.getBytes( ) );
			FileInputStream in = new FileInputStream( f );
			InputStream decrypted = OpenSSL.decrypt( "aes128", key, iv, in );
			byte[] b = Util.streamToBytes( decrypted );
			System.out.println( new String( b ) );
		}
	}


	private static void process( File f, int depth )
	{
		String name = f.getName();
		if ( "CVS".equalsIgnoreCase( name ) )
		{
			return;
		}
		if ( name.toUpperCase().startsWith( "README" ) )
		{
			return;
		}

		if ( f.isDirectory() )
		{
			if ( depth <= 3 )
			{
				File[] files = f.listFiles();
				Arrays.sort( files );
				for ( int i = 0; i < files.length; i++ )
				{
					process( files[ i ], depth + 1 );
				}
			}
			else
			{
System.out.println( "IGNORING [" + f + "].  Directory too deep (" + depth + ")." );
			}
		}
		else
		{
			if ( f.isFile() && f.canRead() )
			{
				String fileName = f.getName();
				int x = fileName.indexOf( '.' );
				if ( x < 0 )
				{
					return;
				}
				String cipher = fileName.substring( 0, x );
				String cipherPadded = Util.pad( cipher, 20, false );
				String filePadded = Util.pad( fileName, 25, false );
				try
				{
					FileInputStream in = new FileInputStream( f );
					byte[] encrypted = Util.streamToBytes( in );
					char[] pwd = "changeit".toCharArray();

					byte[] result = OpenSSL.decrypt( cipher, pwd, encrypted );
					String s = new String( result, "ISO-8859-1" );

					boolean success = "Hello World!".equals( s );
					if ( success )
					{
System.out.println( "SUCCESS \t" + cipherPadded + "\t" + filePadded );
					}
					else
					{
System.out.println( "FAILURE*\t" + cipherPadded + "\t" + filePadded + "\tDECRYPT RESULTS DON'T MATCH" );
					}
				}
				catch ( Exception e )
				{
System.out.println( "FAILURE*\t" + cipherPadded + "\t" + filePadded + "\t" + e );
				e.printStackTrace();
                }
			}
		}
	}

}
