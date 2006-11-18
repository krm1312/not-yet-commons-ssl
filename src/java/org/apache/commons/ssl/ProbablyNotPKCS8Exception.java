package org.apache.commons.ssl;

import java.security.GeneralSecurityException;

/**
 * @author Julius Davies
 * @since 16-Nov-2006
 */
public class ProbablyNotPKCS8Exception extends GeneralSecurityException
{
	public ProbablyNotPKCS8Exception() { super(); }

	public ProbablyNotPKCS8Exception( String s ) { super( s ); }

	// Need to wait for Java 5.0 !
	// public ProbablyNotPKCS8Exception( Throwable t ) { super( t ); }
	// public ProbablyNotPKCS8Exception( String s, Throwable t ) { super( s, t ); }
}
