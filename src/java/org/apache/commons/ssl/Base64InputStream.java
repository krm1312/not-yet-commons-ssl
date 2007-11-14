/*
 * $HeadURL:  $
 * $Revision$
 * $Date$
 *
 * ====================================================================
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */

package org.apache.commons.ssl;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 22-Feb-2007
 */
public class Base64InputStream extends FilterInputStream {
    private final static byte[] LINE_ENDING =
        System.getProperty("line.separator").getBytes();

    final boolean decodeMode;

    byte[] currentLine = null;
    int pos = 0;

    public Base64InputStream(InputStream base64, boolean decodeMode) {
        super(base64);
        this.decodeMode = decodeMode;
    }

    public int read() throws IOException {
        getLine();
        if (currentLine == null) {
            return -1;
        } else {
            byte b = currentLine[pos++];
            if (pos >= currentLine.length) {
                currentLine = null;
            }
            return b;
        }
    }

    public int read(byte b[], int off, int len) throws IOException {
        if (b == null) {
            throw new NullPointerException();
        } else if ((off < 0) || (off > b.length) || (len < 0) ||
                   ((off + len) > b.length) || ((off + len) < 0)) {
            throw new IndexOutOfBoundsException();
        } else if (len == 0) {
            return 0;
        }

        getLine();
        if (currentLine == null) {
            return -1;
        }
        int size = Math.min(currentLine.length - pos, len);
        System.arraycopy(currentLine, pos, b, off, size);
        if (size >= currentLine.length - pos) {
            currentLine = null;
        } else {
            pos += size;
        }
        return size;
    }

    private void getLine() throws IOException {
        if (currentLine == null) {
            if (decodeMode) {
                String line = Util.readLine(in);
                if (line != null) {
                    byte[] b = line.getBytes();
                    currentLine = Base64.decodeBase64(b);
                    pos = 0;
                }
            } else {
                // It will expand to 64 bytes (16 * 4) after base64 encoding!
                byte[] b = Util.streamToBytes(in, 16 * 3);
                if (b.length > 0) {
                    b = Base64.encodeBase64(b);

                    int lfLen = LINE_ENDING.length;
                    currentLine = new byte[b.length + lfLen];
                    System.arraycopy(b, 0, currentLine, 0, b.length);
                    System.arraycopy(LINE_ENDING, 0, currentLine, b.length, lfLen);
                }
            }
        }
    }


}
