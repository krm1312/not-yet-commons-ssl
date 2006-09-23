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

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.cert.Certificate;
import java.util.LinkedList;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.TreeMap;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 28-Feb-2006
 */
public class Util {
    public final static int SIZE_KEY = 0;
    public final static int LAST_READ_KEY = 1;

    public final static byte[] streamToBytes(InputStream in) throws IOException {
        byte[] buf = new byte[4096];
        try {
            int[] status = fill(buf, 0, in);
            int size = status[SIZE_KEY];
            int lastRead = status[LAST_READ_KEY];
            while (lastRead != -1) {
                buf = resizeArray(buf);
                status = fill(buf, size, in);
                size = status[SIZE_KEY];
                lastRead = status[LAST_READ_KEY];
            }
            if (buf.length != size) {
                byte[] smallerBuf = new byte[size];
                System.arraycopy(buf, 0, smallerBuf, 0, size);
                buf = smallerBuf;
            }
        } finally {
            in.close();
        }
        return buf;
    }

    public final static int[] fill(byte[] buf, int offset, InputStream in)
            throws IOException {
        int read = in.read(buf, offset, buf.length - offset);
        int lastRead = read;
        if (read == -1) {
            read = 0;
        }
        while (lastRead != -1 && read + offset < buf.length) {
            lastRead = in.read(buf, offset + read, buf.length - read - offset);
            if (lastRead != -1) {
                read += lastRead;
            }
        }
        int[] status = new int[2];
        status[SIZE_KEY] = offset + read;
        status[LAST_READ_KEY] = lastRead;
        return status;
    }

    public final static byte[] resizeArray(byte[] bytes) {
        byte[] biggerBytes = new byte[bytes.length * 2];
        System.arraycopy(bytes, 0, biggerBytes, 0, bytes.length);
        return biggerBytes;
    }

    public final static void verifyHostName(String host, Socket socket)
            throws IOException {
        boolean isSecure = socket instanceof SSLSocket;
        if (!isSecure) {
            // Don't bother verifying if it's not a secure socket.
            return;
        }
        SSLSocket s = (SSLSocket) socket;
        SSLSession session = s.getSession();
        Certificate[] certs = null;
        try {
            certs = JavaImpl.getPeerCertificates(session);
        } catch (SSLPeerUnverifiedException spue) {
            // let's see if this unearths the real problem:
            s.startHandshake();
            throw spue;
        }
        Certificates.verifyHostName(host, certs);
    }

    public static String pad(String s, int length, boolean left) {
        if (s == null) {
            s = "";
        }
        int diff = length - s.length();
        if (diff == 0) {
            return s;
        } else if (diff > 0) {
            StringBuffer sb = new StringBuffer();
            if (left) {
                for (int i = 0; i < diff; i++) {
                    sb.append(' ');
                }
            }
            sb.append(s);
            if (!left) {
                for (int i = 0; i < diff; i++) {
                    sb.append(' ');
                }
            }
            return sb.toString();
        } else {
            return s;
        }
    }

    public static Map parseArgs(String[] cargs) {
        Map args = new TreeMap();
        Map ARGS_MATCH = Ping.ARGS_MATCH;

        int l = cargs.length;
        final String[] EMPTY_VALUES = {""};
        for (int i = 0; i < l; i++) {
            String k = (String) cargs[i];
            Ping.Arg a = (Ping.Arg) ARGS_MATCH.get(k);
            if (l > i + 1) {
                String v = (String) cargs[++i];
                while (ARGS_MATCH.containsKey(v)) {
                    args.put(a, EMPTY_VALUES);
                    a = (Ping.Arg) ARGS_MATCH.get(v);
                    v = "";
                    if (l > i + 1) {
                        v = (String) cargs[++i];
                    }
                }
                String[] values = new String[1];
                values[0] = v;
                args.put(a, values);
                if (l > i + 1 && !ARGS_MATCH.containsKey(cargs[i + 1])) {
                    LinkedList list = new LinkedList();
                    list.add(v);
                    while (l > i + 1 && !ARGS_MATCH.containsKey(cargs[i + 1])) {
                        v = (String) cargs[++i];
                        list.add(v);
                    }
                    args.put(a, list.toArray(new String[list.size()]));
                }
            } else {
                args.put(a, EMPTY_VALUES);
            }
        }
        return args;
    }

    public static String readLine(InputStream in) throws IOException {
        StringBuffer buf = new StringBuffer(64);
        boolean empty = true;
        int b = in.read();
        while (b != -1) {
            char c = (char) b;
            if (c == '\n' || c == '\r') {
                if (!empty) {
                    return buf.toString();
                }
            } else {
                buf.append(c);
                empty = false;
            }
            b = in.read();
        }
        return b == -1 ? null : buf.toString();
    }

    public static HostPort toAddress(String target, int defaultPort)
            throws UnknownHostException {
        String host = target;
        int port = defaultPort;
        StringTokenizer st = new StringTokenizer(target, ":");
        if (st.hasMoreTokens()) {
            host = st.nextToken().trim();
        }
        if (st.hasMoreTokens()) {
            port = Integer.parseInt(st.nextToken().trim());
        }
        if (st.hasMoreTokens()) {
            throw new IllegalArgumentException("Invalid host: " + target);
        }
        return new HostPort(host, port);
    }


}
