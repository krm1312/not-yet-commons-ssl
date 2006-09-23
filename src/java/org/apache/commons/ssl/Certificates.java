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

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URL;
import java.security.cert.*;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 19-Aug-2005
 */
public class Certificates {

    public final static CertificateFactory CF;
    private final static HashMap crls = new HashMap();
    private final static BouncyHelper bouncyHelper;

    public final static String CRL_EXTENSION = "2.5.29.31";
    public final static String OCSP_EXTENSION = "1.3.6.1.5.5.7.1.1";
    private final static DateFormat DF = new SimpleDateFormat("yyyy/MMM/dd");

    static {
        BouncyHelper bh = null;
        try {
            bh = BouncyHelper.getInstance();
        } catch (Throwable t) {
            System.out.println(t);
        }
        bouncyHelper = bh;
    }

    public interface SerializableComparator extends Comparator, Serializable {
    }

    public final static SerializableComparator COMPARE_BY_EXPIRY =
            new SerializableComparator() {
                public int compare(Object o1, Object o2) {
                    X509Certificate c1 = (X509Certificate) o1;
                    X509Certificate c2 = (X509Certificate) o2;
                    if (c1 == c2) // this deals with case where both are null
                    {
                        return 0;
                    }
                    if (c1 == null)  // non-null is always bigger than null
                    {
                        return -1;
                    }
                    if (c2 == null) {
                        return 1;
                    }
                    if (c1.equals(c2)) {
                        return 0;
                    }
                    Date d1 = c1.getNotAfter();
                    Date d2 = c2.getNotAfter();
                    int c = d1.compareTo(d2);
                    if (c == 0) {
                        String s1 = JavaImpl.getSubjectX500(c1);
                        String s2 = JavaImpl.getSubjectX500(c2);
                        c = s1.compareTo(s2);
                        if (c == 0) {
                            s1 = JavaImpl.getIssuerX500(c1);
                            s2 = JavaImpl.getIssuerX500(c2);
                            c = s1.compareTo(s2);
                            if (c == 0) {
                                BigInteger big1 = c1.getSerialNumber();
                                BigInteger big2 = c2.getSerialNumber();
                                c = big1.compareTo(big2);
                                if (c == 0) {
                                    try {
                                        byte[] b1 = c1.getEncoded();
                                        byte[] b2 = c2.getEncoded();
                                        int len1 = b1.length;
                                        int len2 = b2.length;
                                        int i = 0;
                                        for (; i < len1 && i < len2; i++) {
                                            c = ((int) b1[i]) - ((int) b2[i]);
                                            if (c != 0) {
                                                break;
                                            }
                                        }
                                        if (c == 0) {
                                            c = b1.length - b2.length;
                                        }
                                    } catch (CertificateEncodingException cee) {
                                        // I give up.  They can be equal if they
                                        // really want to be this badly.
                                        c = 0;
                                    }
                                }
                            }
                        }
                    }
                    return c;
                }
            };

    static {
        CertificateFactory cf = null;
        try {
            cf = CertificateFactory.getInstance("X.509");
        } catch (CertificateException ce) {
            ce.printStackTrace(System.out);
        } finally {
            CF = cf;
        }
    }

    public static String toPEMString(X509Certificate cert)
            throws CertificateEncodingException {
        return toString(cert.getEncoded());
    }

    public static String toString(byte[] x509Encoded) {
        byte[] encoded = Base64.encodeBase64(x509Encoded);
        StringBuffer buf = new StringBuffer(encoded.length + 100);
        buf.append("-----BEGIN CERTIFICATE-----\n");
        for (int i = 0; i < encoded.length; i += 64) {
            if (encoded.length - i >= 64) {
                buf.append(new String(encoded, i, 64));
            } else {
                buf.append(new String(encoded, i, encoded.length - i));
            }
            buf.append('\n');
        }
        buf.append("-----END CERTIFICATE-----\n");
        return buf.toString();
    }

    public static String toString(X509Certificate cert) {
        return toString(cert, false);
    }

    public static String toString(X509Certificate cert, boolean htmlStyle) {
        String LINE_ENDING = System.getProperty("line.separator");
        String cn = getCN(cert);
        String startStart = DF.format(cert.getNotBefore());
        String endDate = DF.format(cert.getNotAfter());
        String subject = JavaImpl.getSubjectX500(cert);
        String issuer = JavaImpl.getIssuerX500(cert);
        Iterator crls = getCRLs(cert).iterator();
        if (subject.equals(issuer)) {
            issuer = "self-signed";
        }
        StringBuffer buf = new StringBuffer(128);
        if (htmlStyle) {
            buf.append("<strong class=\"cn\">");
        }
        buf.append(cn);
        if (htmlStyle) {
            buf.append("</strong>");
        }
        buf.append(LINE_ENDING);
        buf.append("Valid: ");
        buf.append(startStart);
        buf.append(" - ");
        buf.append(endDate);
        buf.append(LINE_ENDING);
        buf.append("s: ");
        buf.append(subject);
        buf.append(LINE_ENDING);
        buf.append("i: ");
        buf.append(issuer);
        while (crls.hasNext()) {
            buf.append(LINE_ENDING);
            buf.append("CRL: ");
            buf.append((String) crls.next());
        }
        return buf.toString();
    }

    public final static void verifyHostName(String host, Certificate[] chain)
            throws SSLException {
        verifyHostName(host, (X509Certificate) chain[0]);
    }

    public final static void verifyHostName(String host, X509Certificate cert)
            throws SSLException {
        String cn = getCN(cert);
        boolean match = false;
        if (cn == null) {
            String s = JavaImpl.getSubjectX500(cert);
            throw new SSLException("certificate doesn't contain CN: " + s);
        }

        // Firefox, IE, and java.net.URL support '*.host.com' style CN values
        // (with a wildcard).  Try "https://www.credential.com/" to see an
        // example.  Note:  I'm not allowing things like "*.com".

        // See:  RFC 2595 - search for "*"

        // The CN better have at least two dots if it wants wildcard action.
        boolean wildcard = cn.startsWith("*.") && cn.lastIndexOf('.') > 1;
        if (wildcard) {
            match = host.endsWith(cn.substring(1));
        } else {
            match = host.equals(cn);
        }
        if (!match) {
            throw new SSLException("hostname in certificate didn't match: <" + host + "> != <" + cn + ">");
        }
    }

    public final static String getCN(X509Certificate cert) {
        /*
        // toString() seems to do a better job than getName() on some
        // of the complicated conversions with X500 - at least in SUN's
        // Java 1.4.2_09.
        //
        // For example, getName() gives me this:
        // 1.2.840.113549.1.9.1=#16166a756c6975736461766965734063756362632e636f6d
        //
        // whereas toString() gives me this:
        // EMAILADDRESS=juliusdavies@cucbc.com
        */
        String subjectPrincipal = JavaImpl.getSubjectX500(cert);
        int x = subjectPrincipal.indexOf("CN=");
        int y = subjectPrincipal.indexOf(',', x);
        y = y >= 0 ? y : subjectPrincipal.length();

        /*
        // X500 CommonName parsing is actually much, much harder than this -
        // there are all sorts of special escape characters and hexadecimal
        // conversions to consider (see: <code>RFC 2253</code>).  Maybe
        // toString() is doing these already?  I don't know.
        //
        // (Thanks to Sebastian Hauer's StrictSSLProtocolSocketFactory for
        // pointing out how tricky X500 parsing can be!)
        */
        String cn = subjectPrincipal.substring(x + 3, y);
        return cn;
    }


    public static List getCRLs(X509Extension cert) {

        if (bouncyHelper != null) {
            cert = bouncyHelper.bouncyParse(cert);
        }

        // What follows is a poor man's CRL extractor, for those lacking
        // a BouncyCastle "bcprov.jar" in their classpath.

        // It's a very basic state-machine:  look for a standard URL scheme
        // (such as http), and then start looking for a terminator.  After
        // running hexdump a few times on these things, it looks to me like
        // the UTF-8 value "65533" seems to happen near where these things
        // terminate.  (Of course this stuff is ASN.1 and not UTF-8, but
        // I happen to like some of the functions available to the String
        // object).    - juliusdavies@cucbc.com, May 10th, 2006
        byte[] bytes = cert.getExtensionValue(CRL_EXTENSION);
        LinkedList crls = new LinkedList();
        if (bytes == null) {
            return crls;
        } else {
            String s = "";
            try {
                s = new String(bytes, "UTF-8");
            } catch (UnsupportedEncodingException uee) {
                // We're screwed if this thing has more than one CRL, because
                // the "indeOf( (char) 65533 )" below isn't going to work.
                s = new String(bytes);
            }
            int pos = 0;
            while (pos >= 0) {
                int x = -1, y = s.length();
                int[] indexes = new int[4];
                indexes[0] = s.indexOf("http", pos);
                indexes[1] = s.indexOf("ldap", pos);
                indexes[2] = s.indexOf("file", pos);
                indexes[3] = s.indexOf("ftp", pos);
                Arrays.sort(indexes);
                for (int i = 0; i < indexes.length; i++) {
                    if (indexes[i] >= 0) {
                        x = indexes[i];
                        break;
                    }
                }
                if (x >= 0) {
                    y = s.indexOf((char) 65533, x);
                    String crl = y > x ? s.substring(x, y - 1) : s.substring(x);
                    if (y > x && crl.endsWith("0")) {
                        crl = crl.substring(0, crl.length() - 1);
                    }
                    crls.add(crl);
                    pos = y;
                } else {
                    pos = -1;
                }
            }
        }
        return crls;
    }

    public static void checkValidity(X509Certificate cert)
            throws IOException, CertificateException {
        // String name = cert.getSubjectX500Principal().toString();
        byte[] bytes = cert.getExtensionValue("2.5.29.31");
        String urlToCrl = null;
        if (bytes == null) {
            // log.warn( "Cert doesn't contain X509v3 CRL Distribution Points (2.5.29.31): " + name );
        } else {
            urlToCrl = CRLUtil.getURLToCRL(bytes).trim();
            if ("".equals(urlToCrl)) {
                // log.warn( "URI to CRL is empty: " + name );
            }
        }

        CRLHolder holder = (CRLHolder) crls.get(urlToCrl);
        if (holder == null) {
            holder = new CRLHolder(urlToCrl);
            crls.put(urlToCrl, holder);
        }
        holder.checkValidity(cert);
    }


    private static class CRLHolder {
        private CRL crl;
        private String urlString;
        private long creationTime;

        CRLHolder(String urlString) {
            this.urlString = urlString;
            this.creationTime = System.currentTimeMillis();
        }

        public void checkValidity(X509Certificate cert)
                throws CertificateException {
            cert.checkValidity();
            // String name = cert.getSubjectX500Principal().toString();
            long now = System.currentTimeMillis();
            if (crl == null || now - creationTime > 24 * 60 * 60 * 1000) {
                if (urlString != null) {
                    try {
                        // log.info( "Trying to load CRL [" + urlString + "]" );
                        URL url = new URL(urlString);
                        this.crl = CF.generateCRL(url.openStream());
                    } catch (Exception e) {
                        // log.warn( "Cannot check CRL: " + e );
                    }
                }
            }
            if (crl != null) {
                if (crl.isRevoked(cert)) {
                    // log.warn( "Revoked by CRL [" + urlString + "]: " + name );
                    throw new CertificateException("Revoked by CRL");
                }
            }
        }
    }

}
