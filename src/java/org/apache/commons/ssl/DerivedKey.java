package org.apache.commons.ssl;

/**
 * @author julius
 * @since 7-Nov-2006
 */
public class DerivedKey
{
	public final byte[] key;
	public final byte[] iv;

	DerivedKey( byte[] key, byte[] iv )
	{
		this.key = key;
		this.iv = iv;
	}

}
