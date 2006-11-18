package org.apache.commons.ssl;

import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.Iterator;

/**
 * @author Julius Davies
 * @since 16-Nov-2006
 */
class ASN1Structure
{
	List derIntegers = new LinkedList();
	Set oids = new TreeSet();
	String oid1;
	String oid2;
	String oid3;
	byte[] salt;
	byte[] iv;
	int iterationCount;
	int keySize;
	byte[] bigPayload;
	byte[] smallPayload;

	public String toString()
	{
		StringBuffer buf = new StringBuffer( 256 );
		buf.append( "------ ASN.1 PKCS Structure ------" );
		buf.append( "\noid1:    " );
		buf.append( oid1 );
		if ( oid2 != null )
		{
			buf.append( "\noid2:    " );
			buf.append( oid2 );
		}
		buf.append( "\nsalt:   " );
		if ( salt != null )
		{
			buf.append( PEMUtil.bytesToHex( salt ) );
		}
		else
		{
			buf.append( "[null]" );
		}
		buf.append( "\nic:      " );
		buf.append( Integer.toString( iterationCount ) );
		if ( keySize != 0 )
		{
			buf.append( "\nkeySize: " );
			buf.append( Integer.toString( keySize * 8 ) );
		}
		if ( oid2 != null )
		{
			buf.append( "\noid3:    " );
			buf.append( oid3 );
		}
		if ( oid2 != null )
		{
			buf.append( "\niv:      " );
			if ( iv != null )
			{
				buf.append( PEMUtil.bytesToHex( iv ) );
			}
			else
			{
				buf.append( "[null]" );
			}
		}
		if ( bigPayload != null )
		{
			buf.append( "\nbigPayload-length:   " );
			buf.append( bigPayload.length );
		}
		if ( smallPayload != null )
		{
			buf.append( "\nsmallPayload-length: " );
			buf.append( smallPayload.length );
		}
		if ( !oids.isEmpty() )
		{
			Iterator it = oids.iterator();
			buf.append( "\nAll oids:" );
			while ( it.hasNext() )
			{
				buf.append( "\n" );
				buf.append( (String) it.next() );
			}
		}
		return buf.toString();
	}
}
