/*
 * $Header$
 * $Revision$
 * $Date$
 *
 * ====================================================================
 *
 *  Copyright 2006 The Apache Software Foundation
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */

package org.apache.commons.ssl;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.pkcs.RSAPrivateKeyStructure;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.FileOutputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 27-Feb-2006
 */
public class KeyMaterial extends TrustMaterial {
    private Object keyManagerFactory;
    private String alias;
    private X509Certificate[] associatedChain;

    public KeyMaterial(InputStream jks, char[] password)
            throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException,
            UnrecoverableKeyException {
        this(Util.streamToBytes(jks), password);
    }

    public KeyMaterial(String pathToJksFile, char[] password)
            throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException,
            UnrecoverableKeyException {
        this(new File(pathToJksFile), password);
    }

    public KeyMaterial(File jksFile, char[] password)
            throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException,
            UnrecoverableKeyException {
        this(new FileInputStream(jksFile), password);
    }

    public KeyMaterial(URL urlToJKS, char[] password)
            throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException,
            UnrecoverableKeyException {
        this(urlToJKS.openStream(), password);
    }

    public KeyMaterial(byte[] jks, char[] password)
            throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException,
            UnrecoverableKeyException {
        super(jks, password);
        KeyStore ks = getKeyStore();
        Enumeration en = ks.aliases();
        int privateKeyCount = 0;
        while (en.hasMoreElements()) {
            String alias = (String) en.nextElement();
            if (ks.isKeyEntry(alias)) {
                privateKeyCount++;
                if (privateKeyCount > 1) {
                    throw new KeyStoreException("commons-ssl KeyMaterial only supports keystores with a single private key.");
                }
                this.alias = alias;
            }
        }
	     if ( alias != null )
	     {
		     Certificate[] chain = ks.getCertificateChain(alias);
		     if (chain != null) {
			     X509Certificate[] x509Chain = new X509Certificate[chain.length];
			     for (int i = 0; i < chain.length; i++) {
				     x509Chain[i] = (X509Certificate) chain[i];
			     }
			     this.associatedChain = x509Chain;
		     } else {
			     // is password wrong?
		     }
	     }
	    this.keyManagerFactory = JavaImpl.newKeyManagerFactory(ks, password);
    }

	public KeyMaterial(byte[] key, byte[] certificateChain, char[] password)
	        throws KeyStoreException, CertificateException,
	        NoSuchAlgorithmException, IOException,
	        UnrecoverableKeyException
	{
		TrustMaterial tm = new TrustMaterial( certificateChain );
		Set set = tm.getCertificates();
		X509Certificate[] chain = new X509Certificate[ set.size() ];
		chain = (X509Certificate[]) set.toArray( chain );

		ASN1InputStream in = new ASN1InputStream( key );
		DERObject obj = in.readObject();
		ASN1Sequence seq = (ASN1Sequence) obj;
		RSAPrivateKeyStructure rsa = new RSAPrivateKeyStructure( seq );
		KeyHelper.RSAPrivateCrtKeyImpl spec;
		spec = new KeyHelper.RSAPrivateCrtKeyImpl( rsa.getModulus(),
		                                           rsa.getPublicExponent(),
		                                           rsa.getPrivateExponent(),
		                                           rsa.getPrime1(),
		                                           rsa.getPrime2(),
		                                           rsa.getExponent1(),
		                                           rsa.getExponent2(),
		                                           rsa.getCoefficient() );

		KeyFactory kf = KeyFactory.getInstance( "RSA" );
		PrivateKey pk = null;
		try
		{
			pk = kf.generatePrivate( spec );
		}
		catch( InvalidKeySpecException ikse )
		{
			ikse.printStackTrace( System.out );
		}

System.out.println( pk.getAlgorithm() + " " + pk.getFormat() );		


		KeyStore ks = KeyStore.getInstance("jks");
		ks.load( null, null );
		ks.setKeyEntry( "julius-key", pk, "changeit".toCharArray(), chain );
		FileOutputStream out = new FileOutputStream( "new.jks" );
		ks.store( out, "changeit".toCharArray() );
		out.close();

		System.out.println( PEMUtil.formatRSAPrivateKey( spec ) );

	}

    public Object[] getKeyManagers() {
        return JavaImpl.getKeyManagers(keyManagerFactory);
    }

    public X509Certificate[] getAssociatedCertificateChain() {
        return associatedChain;
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("Usage:  java org.apache.commons.ssl.KeyMaterial [client-cert] [password]");
            System.exit(1);
        }

        String keypath = args[0];
	     String certPath = args[ 1 ];
	     FileInputStream fin = new FileInputStream( args[ 1 ] );
	     byte[] certChain = Util.streamToBytes( fin );

	     List l = PEMUtil.decode( keypath );
	     PEMItem item = (PEMItem) l.get( 0 );
	     KeyMaterial km = new KeyMaterial( item.getDerBytes(), certChain, null );

	     if ( true ) return;

        char[] password = args[1].toCharArray();
        km = new KeyMaterial(keypath, password);
        X509Certificate[] certs = km.getAssociatedCertificateChain();
        for (int i = 0; i < certs.length; i++) {
            System.out.println(Certificates.toString(certs[i]));
            System.out.println(Certificates.toPEMString(certs[i]));
        }
    }
}
