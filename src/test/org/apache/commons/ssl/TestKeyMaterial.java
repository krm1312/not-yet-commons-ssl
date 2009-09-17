package org.apache.commons.ssl;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.SSLSocket;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Iterator;
import java.util.Locale;
import java.util.Arrays;

public class TestKeyMaterial extends TestCase {
    public static final char[] PASSWORD1 = "changeit".toCharArray();
    public static final char[] PASSWORD2 = "itchange".toCharArray();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public TestKeyMaterial(String testName) {
        super(testName);
    }

    public static void main(String args[]) {
        String[] testCaseName = {TestKeyMaterial.class.getName()};
        junit.textui.TestRunner.main(testCaseName);
    }

    public static Test suite() {
        return new TestSuite(TestKeyMaterial.class);
    }

    public void testDSA_RSA_Mix() throws Exception {

    }


    public void testKeystores() throws Exception {
        String samplesDir = "samples/keystores";
        File dir = new File(samplesDir);
        String[] files = dir.list();
        Arrays.sort(files, String.CASE_INSENSITIVE_ORDER);
        for (String f : files) {
            String F = f.toUpperCase(Locale.ENGLISH);
            if (F.endsWith(".KS") || F.indexOf("PKCS12") >= 0) {
                examineKeyStore(samplesDir, f, null);
            } else if (F.endsWith(".PEM")) {
                examineKeyStore(samplesDir, f, "rsa.key");
            }
        }
    }

    private static void examineKeyStore(String dir, String fileName, String file2) throws Exception {
        String FILENAME = fileName.toUpperCase(Locale.ENGLISH);
        int y = FILENAME.lastIndexOf('.');
        int x = FILENAME.lastIndexOf('.', y - 1);

        String type = FILENAME.substring(x + 1, y).toUpperCase(Locale.ENGLISH);
        boolean hasMultiPassword = FILENAME.indexOf(".2PASS.") >= 0;

        FileInputStream fin = new FileInputStream(dir + "/" + fileName);
        System.out.println("Testing KeyMaterial: " + dir + "/" + fileName);        
        byte[] keystoreBytes = Util.streamToBytes(fin);
        char[] pass1 = PASSWORD1;
        char[] pass2 = PASSWORD1;
        if (hasMultiPassword) {
            pass2 = PASSWORD2;
        }

        file2 = file2 != null ? dir + "/" + file2 : null;

        Date today = new Date();
        KeyMaterial km = new KeyMaterial(dir + "/" + fileName, file2, pass1, pass2);
        assertEquals("keymaterial-contains-1-alias", 1, km.getAliases().size());
        Iterator it509 = km.getAssociatedCertificateChains().iterator();
        while (it509.hasNext()) {
            X509Certificate[] cert = (X509Certificate[]) it509.next();
            for (int i = 0; i < cert.length; i++) {
                assertTrue("certchain-valid-dates", cert[i].getNotAfter().after(today));
            }
        }

        SSLServer server = new SSLServer();
        server.setKeyMaterial(km);
        ServerSocket ss = server.createServerSocket(0);
        int port = ss.getLocalPort();
        startServerThread(ss);
        Thread.sleep(1);


        SSLClient client = new SSLClient();
        client.setTrustMaterial(TrustMaterial.TRUST_ALL);
        client.setCheckHostname(false);
        SSLSocket s = (SSLSocket) client.createSocket("localhost", port);
        Certificate[] certs = s.getSession().getPeerCertificates();
        InputStream in = s.getInputStream();
        Util.streamToBytes(in);
        in.close();
        // System.out.println(Certificates.toString((X509Certificate) certs[0]));
        s.close();       
    }


    private static void startServerThread(final ServerSocket ss) {
        Runnable r = new Runnable() {
            public void run() {
                try {
                    Socket s = ss.accept();
                    OutputStream out = s.getOutputStream();
                    Thread.sleep(1);
                    out.write("Hello From Server\n".getBytes());
                    Thread.sleep(1);
                    out.close();
                    s.close();
                } catch (Exception e) {

                } finally {
                    // System.out.println("Test ssl server on port " + port + " finished.");
                }
            }
        };

        new Thread(r).start();
    }

}
