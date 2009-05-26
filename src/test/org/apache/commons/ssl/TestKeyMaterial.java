package org.apache.commons.ssl;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.FileInputStream;
import java.security.Security;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.Iterator;
import java.util.Date;

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
        for (String f : files) {
            String F = f.toUpperCase(Locale.ENGLISH);
            if (F.endsWith(".KS")) {
                examineKeyStore(samplesDir, f);
            }
        }
    }

    private static void examineKeyStore(String dir, String fileName) throws Exception {
        String FILENAME = fileName.toUpperCase(Locale.ENGLISH);
        int y = FILENAME.lastIndexOf('.');
        int x = FILENAME.lastIndexOf('.', y - 1);

        String type = FILENAME.substring(x + 1, y).toUpperCase(Locale.ENGLISH);
        boolean hasMultiPassword = FILENAME.indexOf(".2PASS.") >= 0;

        FileInputStream fin = new FileInputStream(dir + "/" + fileName);
        byte[] keystoreBytes = Util.streamToBytes(fin);
        char[] pass1 = PASSWORD1;
        char[] pass2 = PASSWORD1;
        if (hasMultiPassword) {
            pass2 = PASSWORD2;
        }

        Date today = new Date();
        KeyMaterial km = new KeyMaterial(dir + "/" + fileName, pass1, pass2);
        assertEquals("keymaterial-contains-1-alias", 1, km.getAliases().size());
        Iterator it509 = km.getAssociatedCertificateChains().iterator();
        while (it509.hasNext()) {
            X509Certificate[] cert = (X509Certificate[]) it509.next();
            for (int i = 0; i < cert.length; i++) {
                assertTrue("certchain-valid-dates", cert[i].getNotAfter().after(today));
            }
        }



    }

}
