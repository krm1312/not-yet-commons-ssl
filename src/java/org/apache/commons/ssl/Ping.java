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

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 30-Mar-2006
 */
public class Ping {
    protected static SortedSet ARGS = new TreeSet();
    protected static Map ARGS_MATCH = new HashMap();
    protected final static Arg ARG_TARGET = new Arg("-t", "--target", "[hostname[:port]]             default port=443", true);
    protected final static Arg ARG_BIND = new Arg("-b", "--bind", "[hostname[:port]]             default port=0 \"ANY\"");
    protected final static Arg ARG_PROXY = new Arg("-r", "--proxy", "[hostname[:port]]             default port=80");
    protected final static Arg ARG_CLIENT_CERT = new Arg("-c", "--client-cert", "[path to client certificate]  *.jks or *.pfx");
    protected final static Arg ARG_PASSWORD = new Arg("-p", "--password", "[client cert password]");

    private static HostPort target;
    private static HostPort local;
    private static HostPort proxy;
    private static InetAddress targetAddress;
    private static InetAddress localAddress;
    private static int targetPort = 443;
    private static int localPort = 0;
    private static File clientCert;
    private static char[] password;

    static {
        ARGS = Collections.unmodifiableSortedSet(ARGS);
        ARGS_MATCH = Collections.unmodifiableMap(ARGS_MATCH);
    }

    public static void main(String[] args) throws Exception {
        boolean showUsage = args.length == 0;
        Exception parseException = null;
        if (!showUsage) {
            try {
                parseArgs(args);
            } catch (Exception e) {
                parseException = e;
                showUsage = true;
            }
        }
        if (showUsage) {
            if (parseException != null) {
                System.out.println();
                System.out.println("* Error: " + parseException.getMessage() + ".");
                System.out.println();
            }
            System.out.println("Usage:  java -jar commons-ssl.jar [options]");
            System.out.println("Options:   (*=required)");
            Iterator it = ARGS.iterator();
            while (it.hasNext()) {
                Arg a = (Arg) it.next();
                String s = Util.pad(a.shortArg, 3, false);
                String l = Util.pad(a.longArg, 18, false);
                String required = a.isRequired ? "*" : " ";
                String d = a.description;
                System.out.println(required + "  " + s + " " + l + " " + d);
            }
            System.out.println();
            String example = "java -jar commons-ssl.jar -t cucbc.com:443 -c ./client.pfx -p `cat ./pass.txt` ";
            System.out.println("Example:");
            System.out.println();
            System.out.println(example);
            System.out.println();
            System.exit(1);
            return;
        }

        SSLClient ssl = new SSLClient();
        Socket s = null;
        InputStream in = null;
        OutputStream out = null;
        Exception socketException = null;
        Exception verifyException = null;
        try {
            try {
                ssl.setDoVerify(false);
                ssl.addTrustMaterial(TrustMaterial.TRUST_ALL);
                if (clientCert != null) {
                    KeyMaterial km = new KeyMaterial(clientCert, password);
                    if (password != null) {
                        for (int i = 0; i < password.length; i++) {
                            password[i] = 0;
                        }
                    }
                    ssl.setKeyMaterial(km);
                }
                ssl.setSoTimeout(10000);
                ssl.setConnectTimeout(5000);

                if (proxy != null) {
                    s = new Socket(proxy.host, proxy.port,
                            local.addr, local.port);
                    s.setSoTimeout(10000);
                    in = s.getInputStream();
                    out = s.getOutputStream();
                    String targetHost = target.host;
                    String line1 = "CONNECT " + targetHost + ":" + targetPort + " HTTP/1.1\r\n";
                    String line2 = "Proxy-Connection: keep-alive\r\n";
                    String line3 = "Host: " + targetHost + "\r\n\r\n";
                    out.write(line1.getBytes());
                    out.write(line2.getBytes());
                    out.write(line3.getBytes());
                    out.flush();

                    String read1 = Util.readLine(in);
                    if (read1.startsWith("HTTP/1.1 200")) {
                        int avail = in.available();
                        in.skip(avail);
                        Thread.yield();
                        avail = in.available();
                        while (avail != 0) {
                            in.skip(avail);
                            Thread.yield();
                            avail = in.available();
                        }
                        s = ssl.createSocket(s, targetHost, targetPort, true);
                    } else {
                        System.out.print(line1);
                        System.out.print(line2);
                        System.out.print(line3);
                        System.out.println("Server returned unexpected proxy response!");
                        System.out.println("=============================================");
                        System.out.println(read1);
                        String line = Util.readLine(in);
                        while (line != null) {
                            System.out.println(line);
                            line = Util.readLine(in);
                        }
                        System.exit(1);
                    }
                } else {
                    s = ssl.createSocket(targetAddress, targetPort,
                            localAddress, localPort);
                }

                String line1 = "HEAD / HTTP/1.1";
                String line2 = "Host: " + targetAddress.getHostName();
                byte[] crlf = {'\r', '\n'};

                System.out.println("Writing: ");
                System.out.println("================================================================================");
                System.out.println(line1);
                System.out.println(line2);
                System.out.println();

                out = s.getOutputStream();
                out.write(line1.getBytes());
                out.write(crlf);
                out.write(line2.getBytes());
                out.write(crlf);
                out.write(crlf);
                out.flush();

                in = s.getInputStream();
                int c = in.read();
                StringBuffer buf = new StringBuffer();
                System.out.println("Reading: ");
                System.out.println("================================================================================");
                while (c >= 0) {
                    byte b = (byte) c;
                    buf.append((char) b);
                    System.out.print((char) b);
                    if (-1 == buf.toString().indexOf("\r\n\r\n")) {
                        c = in.read();
                    } else {
                        break;
                    }
                }
            } catch (Exception e) {
                socketException = e;
            }
            try {
                X509Certificate[] chain = ssl.getCurrentServerChain();
                if (chain != null) {
                    String hostName = targetAddress.getHostName();
                    Certificates.verifyHostName(hostName, chain);
                }
            } catch (Exception e) {
                verifyException = e;
            }
        } finally {
            if (out != null) {
                out.close();
            }
            if (in != null) {
                in.close();
            }
            if (s != null) {
                s.close();
            }

            X509Certificate[] peerChain = ssl.getCurrentServerChain();
            if (peerChain != null) {
                String title = "Server Certificate Chain for: ";
                title = peerChain.length > 1 ? title : "Server Certificate for: ";
                System.out.println(title + "[" + target + "]");
                System.out.println("================================================================================");
                for (int i = 0; i < peerChain.length; i++) {
                    X509Certificate cert = peerChain[i];
                    String certAsString = Certificates.toString(cert);
                    String certAsPEM = Certificates.toPEMString(cert);
                    System.out.println(certAsString);
                    System.out.print(certAsPEM);
                }
            }
            if (verifyException != null) {
                verifyException.printStackTrace();
                System.out.println();
            }
            if (socketException != null) {
                socketException.printStackTrace();
                System.out.println();
            }
        }
    }


    public static class Arg implements Comparable {
        public final String shortArg;
        public final String longArg;
        public final String description;
        public final boolean isRequired;
        private final int id;

        public Arg(String s, String l, String d) {
            this(s, l, d, false);
        }

        public Arg(String s, String l, String d, boolean isRequired) {
            this.isRequired = isRequired;
            this.shortArg = s;
            this.longArg = l;
            this.description = d;
            this.id = ARGS.size();
            ARGS.add(this);
            if (s != null && s.length() >= 2) {
                ARGS_MATCH.put(s, this);
            }
            if (l != null && l.length() >= 3) {
                ARGS_MATCH.put(l, this);
            }
        }

        public int compareTo(Object o) {
            return id - ((Arg) o).id;
        }

        public String toString() {
            return shortArg + "/" + longArg;
        }
    }

    private static void parseArgs(String[] cargs) throws Exception {
        Map args = Util.parseArgs(cargs);
        Iterator it = args.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry entry = (Map.Entry) it.next();
            Arg arg = (Arg) entry.getKey();
            String[] values = (String[]) entry.getValue();
            if (arg == ARG_TARGET) {
                target = Util.toAddress(values[0], 443);
                targetAddress = target.addr;
                targetPort = target.port;
            } else if (arg == ARG_BIND) {
                local = Util.toAddress(values[0], 443);
                localAddress = local.addr;
                localPort = local.port;
            } else if (arg == ARG_PROXY) {
                proxy = Util.toAddress(values[0], 80);
            } else if (arg == ARG_CLIENT_CERT) {
                clientCert = new File(values[0]);
            } else if (arg == ARG_PASSWORD) {
                password = values[0].toCharArray();
            }
        }
        args.clear();
        for (int i = 0; i < cargs.length; i++) {
            cargs[i] = null;
        }

        if (targetAddress == null) {
            throw new IllegalArgumentException("\"" + ARG_TARGET + "\" is mandatory");
        }
    }
}
