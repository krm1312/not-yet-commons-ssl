package org.apache.commons.ssl;

import java.security.GeneralSecurityException;

/**
 * @author julius
 * @since 16-Nov-2006
 */
public class ProbablyBadPasswordException extends GeneralSecurityException
{
	public ProbablyBadPasswordException() { super(); }

	public ProbablyBadPasswordException( String s ) { super( s ); }

	// Need to wait for Java 5.0 !
	// public ProbablyBadPasswordException( Throwable t ) { super( t ); }
	// public ProbablyBadPasswordException( String s, Throwable t ) { super( s, t ); }

}
