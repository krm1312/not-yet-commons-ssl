package org.apache.commons.ssl;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import java.io.File;
import java.io.FileInputStream;
import java.util.Arrays;
import java.util.Locale;

public class TestPKCS8Key extends TestCase {

    public TestPKCS8Key(String testName) {
        super(testName);
    }

    public static void main(String args[]) {
        String[] testCaseName = {TestPKCS8Key.class.getName()};
        junit.textui.TestRunner.main(testCaseName);
    }

    public static Test suite() {
        return new TestSuite(TestPKCS8Key.class);
    }

    public void testDSA() throws Exception {
        checkFiles("dsa");
    }

    public void testRSA() throws Exception {
        checkFiles("rsa");
    }

    private static void checkFiles(String type) throws Exception {
        String password = "changeit";
        File dir = new File("samples/" + type);
        File[] files = dir.listFiles();
        byte[] original = null;
        for (int i = 0; i < files.length; i++) {
            File f = files[i];
            String filename = f.getName();
            String FILENAME = filename.toUpperCase(Locale.ENGLISH);
            if (!FILENAME.endsWith(".PEM") && !FILENAME.endsWith(".DER")) {
                // not a sample file
                continue;
            }

            FileInputStream in = new FileInputStream(f);
            byte[] bytes = Util.streamToBytes(in);
            PKCS8Key key = new PKCS8Key(bytes, password.toCharArray());
            byte[] decrypted = key.getDecryptedBytes();
            if (original == null) {
                original = decrypted;
            } else {
                boolean identical = Arrays.equals(original, decrypted);
                assertTrue(f.getCanonicalPath() + " - all " + type + " samples decrypt to same key", identical);
            }
        }

    }
}
