package org.apache.commons.ssl;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * @author Julius Davies
 * @since Jul 7, 2004
 */
public class Version
{
	public static final String VERSION = "$Name$";
	public static final String COMPILE_TIME;

	static
	{
		String s = null;
		try
		{
			s = CompileTime.getCompileTimeString( Version.class );
		}
		catch ( NoClassDefFoundError e )
		{
			s = null;
		}
		COMPILE_TIME = s;
	}

	public static String versionString()
	{
		if ( COMPILE_TIME != null )
		{
			return CompileTime.formatVersion( VERSION, COMPILE_TIME );
		}
		else
		{
			return VERSION;
		}
	}

	public static void main( String[] args )
	{
		System.out.println( versionString() );
	}

	public String toString()
	{
		return versionString();
	}


	/**
	 * Searches through a jar file to the find the most recent timestamp of
	 * all the class files.
	 */
	private static class CompileTime
	{
		private final static String PATTERN = ".jar!";
		private final static String PREFIX = "file:";
		private final static String DF_FORMAT = "zzz:yyyy-MM-dd/HH:mm:ss.SSS";
		private final static DateFormat DF = new SimpleDateFormat( DF_FORMAT );

		public static String getCompileTimeString( Class clazz )
		{
			String s = clazz.getName();
			s = "/" + s.replace( '.', '/' ) + ".class";
			return getCompileTimeString( s );
		}

		private static String getCompileTimeString( String resource )
		{
			try
			{
				Date d = getCompileTime( resource );
				return d != null ? DF.format( d ) : "[unknown]";
			}
			catch ( IOException ioe )
			{
				return ioe.toString();
			}
		}

		public static Date getCompileTime( String resource ) throws IOException
		{
			URL url = CompileTime.class.getResource( resource );
			if ( url != null )
			{
				String urlString = url.getFile();
				String fileLocation = null;
				int i = urlString.indexOf( PATTERN );
				if ( i > 0 )
				{
					int x = i + PATTERN.length() - 1;
					fileLocation = urlString.substring( 0, x );
					if ( fileLocation.startsWith( PREFIX ) )
					{
						fileLocation = fileLocation.substring( PREFIX.length() );
					}
					JarFile jf = new JarFile( fileLocation );
					long newestTime = 0;
					Enumeration entries = jf.entries();
					while ( entries.hasMoreElements() )
					{
						JarEntry entry = (JarEntry) entries.nextElement();
						if ( entry.getName().endsWith( ".class" ) )
						{
							newestTime = Math.max( newestTime, entry.getTime() );
						}
					}
					if ( newestTime > 0 )
					{
						return new Date( newestTime );
					}
				}
				else
				{
					File f = new File( urlString );
					try
					{
						return new Date( f.lastModified() );
					}
					catch ( Exception e )
					{
					}
				}
			}
			return null;
		}

		public static String formatVersion( String version, String compileTime )
		{
			StringBuffer buf = new StringBuffer();
			buf.append( version );
			buf.append( " compiled=[" );
			buf.append( compileTime );
			buf.append( "]" );
			return buf.toString();
		}

	}

}
