package org.apache.commons.ssl;

import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.interfaces.RSAPrivateCrtKey;
import java.math.BigInteger;

/**
 * @author Julius Davies
 * @since 13-Aug-2006
 */
public class KeyHelper
{
	public static class RSAPrivateCrtKeyImpl extends RSAPrivateCrtKeySpec
	      implements RSAPrivateCrtKey
	{
		public RSAPrivateCrtKeyImpl(BigInteger modulus, BigInteger publicExponent,
		                            BigInteger privateExponent, BigInteger primeP,
		                            BigInteger primeQ, BigInteger primeExponentP,
		                            BigInteger primeExponentQ,
		                            BigInteger crtCoefficient) {
			super( modulus, publicExponent, privateExponent, primeP, primeQ,
			       primeExponentP, primeExponentQ, crtCoefficient );
		}

		public byte[] getEncoded() { return null; }
		public String getAlgorithm() { return "RSA"; }
		public String getFormat() { return "PEM"; }
   }

}
