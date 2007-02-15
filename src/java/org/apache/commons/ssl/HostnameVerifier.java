/*
 * $HeadURL: http://svn.apache.org/repos/asf/jakarta/httpcomponents/httpclient/trunk/src/java/org/apache/http/conn/ssl/HostnameVerifier.java $
 * $Revision$
 * $Date$
 *
 * ====================================================================
 *
 *  Copyright 2002-2004 The Apache Software Foundation
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
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;

/**
 * Interface for checking if a hostname matches the names stored inside the
 * server's X.509 certificate.  Implements javax.net.ssl.HostnameVerifier, but
 * we don't actually use that interface.  Instead we added some methods that
 * take String parameters (instead of javax.net.ssl.HostnameVerifier's
 * SSLSession).  JUnit is a lot easier this way!  :-)
 * <p/>
 * We provide the HostnameVerifier.DEFAULT, HostnameVerifier.STRICT, and
 * HostnameVerifier.ALLOW_ALL implementations.  But feel free to define
 * your own implementation!
 * <p/>
 * Inspired by Sebastian Hauer's original StrictSSLProtocolSocketFactory in the
 * HttpClient "contrib" repository.
 *
 * @author Julius Davies
 * @author <a href="mailto:hauer@psicode.com">Sebastian Hauer</a>
 * @since 8-Dec-2006
 */
public interface HostnameVerifier extends javax.net.ssl.HostnameVerifier {

    boolean verify(String host, SSLSession session);

    void verify(String[] hosts, SSLSocket ssl) throws IOException;

    void verify(String[] hosts, X509Certificate cert) throws SSLException;

    /**
     * Checks to see if the supplied hostname matches any of the supplied CNs
     * or "DNS" Subject-Alts.  Most implementations only look at the first CN,
     * and ignore any additional CNs.  Most implementations do look at all of
     * the "DNS" Subject-Alts. The CNs or Subject-Alts may contain wildcards
     * according to RFC 2818.
     *
     * @param cns         CN fields, in order, as extracted from the X.509
     *                    certificate.
     * @param subjectAlts Subject-Alt fields of type 2 ("DNS"), as extracted
     *                    from the X.509 certificate.
     * @param hosts       The array of hostnames to verify.
     * @throws SSLException If verification failed.
     */
    void verify(String[] hosts, String[] cns, String[] subjectAlts)
          throws SSLException;


    /**
     * The DEFAULT HostnameVerifier works the same way as Curl and Firefox.
     * <p/>
     * The hostname must match either the first CN, or any of the subject-alts.
     * A wildcard can occur in the CN, and in any of the subject-alts.
     * <p/>
     * The only difference between DEFAULT and STRICT is that a wildcard (such
     * as "*.foo.com") with DEFAULT matches all subdomains, including
     * "a.b.foo.com".
     */
    public final static HostnameVerifier DEFAULT =
          new AbstractVerifier() {
              public final void verify(final String[] hosts, final String[] cns,
                                       final String[] subjectAlts)
                    throws SSLException {
                  verify(hosts, cns, subjectAlts, false);
              }

              public final String toString() { return "DEFAULT"; }
          };


    /**
     * The DEFAULT_AND_LOCALHOST HostnameVerifier works like the DEFAULT
     * one with one additional relaxation:  a host of "localhost",
     * "localhost.localdomain", "127.0.0.1", "::1" will always pass, no matter
     * what is in the server's certificate.
     */
    public final static HostnameVerifier DEFAULT_AND_LOCALHOST =
          new AbstractVerifier() {

              public final void verify(final String[] hosts, final String[] cns,
                                       final String[] subjectAlts)
                    throws SSLException {
                  if (isLocalhost(hosts[0])) {
                      return;
                  }
                  verify(hosts, cns, subjectAlts, false);
              }

              public final String toString() { return "DEFAULT_AND_LOCALHOST"; }
          };

    /**
     * The Strict HostnameVerifier works the same way as Sun Java 1.4, Sun
     * Java 5, Sun Java 6-rc.  It's also pretty close to IE6.  This
     * implementation appears to be compliant with RFC 2818 for dealing with
     * wildcards.
     * <p/>
     * The hostname must match either the first CN, or any of the subject-alts.
     * A wildcard can occur in the CN, and in any of the subject-alts.  The
     * one divergence from IE6 is how we only check the first CN.  IE6 allows
     * a match against any of the CNs present.  We decided to follow in
     * Sun Java 1.4's footsteps and only check the first CN.  (If you need
     * to check all the CN's, feel free to write your own implementation!).
     * <p/>
     * A wildcard such as "*.foo.com" matches only subdomains in the same
     * level, for example "a.foo.com".  It does not match deeper subdomains
     * such as "a.b.foo.com".
     */
    public final static HostnameVerifier STRICT =
          new AbstractVerifier() {
              public final void verify(final String[] host, final String[] cns,
                                       final String[] subjectAlts)
                    throws SSLException {
                  verify(host, cns, subjectAlts, true);
              }

              public final String toString() { return "STRICT"; }
          };

    /**
     * The ALLOW_ALL HostnameVerifier essentially turns hostname verification
     * off.  This implementation is a no-op, and never throws the SSLException.
     */
    public final static HostnameVerifier ALLOW_ALL =
          new AbstractVerifier() {
              public final void verify(final String[] host, final String[] cns,
                                       final String[] subjectAlts) {
                  // Allow everything - so never blowup.
              }

              public final String toString() { return "ALLOW_ALL"; }
          };

    abstract class AbstractVerifier implements HostnameVerifier {

        /**
         * This contains a list of 2nd-level domains that aren't allowed to
         * have wildcards when combined with country-codes.
         * For example: [*.co.uk].
         * <p/>
         * The [*.co.uk] problem is an interesting one.  Should we just hope
         * that CA's would never foolishly allow such a certificate to happen?
         * Looks like we're the only implementation guarding against this.
         * Firefox, Curl, Sun Java 1.4, 5, 6 don't bother with this check.
         */
        private final static String[] BAD_COUNTRY_2LDS =
              { "ac", "co", "com", "ed", "edu", "go", "gouv", "gov", "info",
                "lg", "ne", "net", "or", "org" };

        private final static String[] LOCALHOSTS = { "::1", "127.0.0.1",
                                                     "localhost",
                                                     "localhost.localdomain" };


        static {
            // Just in case developer forgot to manually sort the array.  :-)
            Arrays.sort(BAD_COUNTRY_2LDS);
            Arrays.sort(LOCALHOSTS);
        }

        protected AbstractVerifier() {}

        public final void verify(String host[], SSLSocket ssl)
              throws IOException {
            if(host == null) {
                throw new NullPointerException("host to verify is null");
            }

            SSLSession session = ssl.getSession();
            if(session == null) {
                // In our experience this only happens under IBM 1.4.x when
                // spurious (unrelated) certificates show up in the server'
                // chain.  Hopefully this will unearth the real problem:
                InputStream in = ssl.getInputStream();
                in.available();
                /*
                  If you're looking at the 2 lines of code above because
                  you're running into a problem, you probably have two
                  options:

                    #1.  Clean up the certificate chain that your server
                         is presenting (e.g. edit "/etc/apache2/server.crt"
                         or wherever it is your server's certificate chain
                         is defined).

                                               OR

                    #2.   Upgrade to an IBM 1.5.x or greater JVM, or switch
                          to a non-IBM JVM.
                */

                // If ssl.getInputStream().available() didn't cause an
                // exception, maybe at least now the session is available?
                session = ssl.getSession();
                if(session == null) {
                    // If it's still null, probably a startHandshake() will
                    // unearth the real problem.
                    ssl.startHandshake();

                    // Okay, if we still haven't managed to cause an exception,
                    // might as well go for the NPE.  Or maybe we're okay now?
                    session = ssl.getSession();
                }
            }
            Certificate[] certs;
            try {
               certs = session.getPeerCertificates();
            } catch(SSLPeerUnverifiedException spue) {
                InputStream in = ssl.getInputStream();
                in.available();
                // Didn't trigger anything interesting?  Okay, just throw
                // original.
                throw spue;
            }
            X509Certificate x509 = (X509Certificate) certs[0];
            verify(host, x509);
        }

        public final boolean verify(String host, SSLSession session) {
            try {
                Certificate[] certs = session.getPeerCertificates();
                X509Certificate x509 = (X509Certificate) certs[0];
                verify(new String[] { host }, x509);
                return true;
            }
            catch(SSLException e) {
                return false;
            }
        }

        public final void verify(String[] host, X509Certificate cert)
              throws SSLException {
            String[] cns = Certificates.getCNs(cert);
            String[] subjectAlts = Certificates.getDNSSubjectAlts(cert);
            verify(host, cns, subjectAlts);
        }

        public final void verify(final String[] hosts, final String[] cns,
                                 final String[] subjectAlts,
                                 final boolean strictWithSubDomains)
              throws SSLException {
            // Build up lists of allowed hosts For logging/debugging purposes.
            StringBuffer buf = new StringBuffer(32);
            buf.append('<');
            for (int i = 0; i < hosts.length; i++) {
                String h = hosts[i];
                h = h != null ? h.trim().toLowerCase() : "";
                hosts[i] = h;
                if (i > 0) {
                    buf.append('/');
                }
                buf.append(h);
            }
            buf.append('>');
            String hostnames = buf.toString();
            // Build the list of names we're going to check.  Our DEFAULT and
            // STRICT implementations of the HostnameVerifier only use the
            // first CN provided.  All other CNs are ignored.
            // (Firefox, wget, curl, Sun Java 1.4, 5, 6 all work this way).
            LinkedList names = new LinkedList();
            if(cns != null && cns.length > 0 && cns[0] != null) {
                names.add(cns[0]);
            }
            if(subjectAlts != null) {
                for(int i = 0; i < subjectAlts.length; i++) {
                    if(subjectAlts[i] != null) {
                        names.add(subjectAlts[i]);
                    }
                }
            }
            if(names.isEmpty()) {
                String msg = "Certificate for " + hosts[0] + " doesn't contain CN or DNS subjectAlt";
                throw new SSLException(msg);
            }

            // StringBuffer for building the error message.
            buf = new StringBuffer();

            boolean match = false;
            out:
            for(Iterator it = names.iterator(); it.hasNext();) {
                // Don't trim the CN, though!
                String cn = (String) it.next();
                cn = cn.toLowerCase();
                // Store CN in StringBuffer in case we need to report an error.
                buf.append(" <");
                buf.append(cn);
                buf.append('>');
                if(it.hasNext()) {
                    buf.append(" OR");
                }

                // The CN better have at least two dots if it wants wildcard
                // action.  It also can't be [*.co.uk] or [*.co.jp] or
                // [*.org.uk], etc...
                boolean doWildcard = cn.startsWith("*.") &&
                                     cn.lastIndexOf('.') >= 0 &&
                                     !isIP4Address(cn) &&
                                     acceptableCountryWildcard(cn);

                for ( int i = 0; i < hosts.length; i++ )
                {
                    final String hostName = hosts[i].trim().toLowerCase();
                    if(doWildcard) {
                        match = hostName.endsWith(cn.substring(1));
                        if(match && strictWithSubDomains) {
                            // If we're in strict mode, then [*.foo.com] is not
                            // allowed to match [a.b.foo.com]
                            match = countDots(hostName) == countDots(cn);
                        }
                    } else {
                        match = hostName.equals(cn);
                    }
                    if(match) {
                        break out;
                    }
                }
            }
            if(!match) {
                throw new SSLException("hostname in certificate didn't match: " + hostnames + " !=" + buf);
            }
        }	    	     

        public static boolean isIP4Address(String cn) {
            boolean isIP4 = true;
            String tld = cn;
            int x = cn.lastIndexOf('.');
            if ( x >= 0 && x + 1 < cn.length() ) {
                tld = cn.substring(x + 1);
            }
            for (int i = 0; i < tld.length(); i++) {
                if (!Character.isDigit(tld.charAt(0))) {
                    isIP4 = false;
                    break;
                }
            }
            return isIP4;
        }

        public static boolean acceptableCountryWildcard(String cn) {
            int cnLen = cn.length();
            if(cnLen >= 7 && cnLen <= 9) {
                // Look for the '.' in the 3rd-last position:
                if(cn.charAt(cnLen - 3) == '.') {
                    // Trim off the [*.] and the [.XX].
                    String s = cn.substring(2, cnLen - 3);
                    // And test against the sorted array of bad 2lds:
                    int x = Arrays.binarySearch(BAD_COUNTRY_2LDS, s);
                    return x < 0;
                }
            }
            return true;
        }

        public static boolean isLocalhost(String host)
        {
            host = host != null ? host.trim().toLowerCase() : "";
            if (host.startsWith("::1")) {
                int x = host.lastIndexOf('%');
                if (x >= 0) {
                    host = host.substring(0, x);
                }
            }
            int x = Arrays.binarySearch(LOCALHOSTS, host);
            return x >= 0;
        }

        /**
         * Counts the number of dots "." in a string.
         * @param s  string to count dots from
         * @return  number of dots
         */
        public static int countDots(final String s) {
            int count = 0;
            for(int i = 0; i < s.length(); i++) {
                if(s.charAt(i) == '.') {
                    count++;
                }
            }
            return count;
        }
    }

}
