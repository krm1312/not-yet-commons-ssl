package org.apache.commons.ssl;

import junit.framework.TestCase;
import junit.framework.TestSuite;
import junit.framework.Test;

import java.util.Random;
import java.util.Arrays;

public class TestOpenSSL extends TestCase {

public TestOpenSSL(String testName) {
        super(testName);
    }

    public static void main(String args[]) {
        String[] testCaseName = { TestOpenSSL.class.getName() };
        junit.textui.TestRunner.main(testCaseName);
    }

    public static Test suite() {
        return new TestSuite(TestOpenSSL.class);
    }


    public void encTest( String cipher ) throws Exception {
        Random random = new Random();
        char[] pwd = {'!','E','i','k','o','?'};

        for ( int i = 0; i < 4567; i++ ) {
            byte[] buf = new byte[ i ];
            random.nextBytes(buf);
            byte[] enc = OpenSSL.encrypt( cipher, pwd, buf );
            byte[] dec = OpenSSL.decrypt( cipher, pwd, enc );
            boolean result = Arrays.equals(buf, dec);
            if ( !result ) {
                System.out.println();
                System.out.println( "Failed on : " + i );
            }
            assertTrue( result );
        }

        for ( int i = 5; i < 50; i++ ) {
            int testSize = ( i * 1000 ) + 123;
            byte[] buf = new byte[ testSize ];
            random.nextBytes(buf);
            byte[] enc = OpenSSL.encrypt( cipher, pwd, buf );
            byte[] dec = OpenSSL.decrypt( cipher, pwd, enc );
            boolean result = Arrays.equals(buf, dec);
            if ( !result ) {
                System.out.println();
                System.out.println( "Failed on : " + testSize );
            }
            assertTrue( result );
        }

    }

    public void testDES3Bytes() throws Exception {
        encTest("des3");
    }

    public void testAES128Bytes() throws Exception {
        encTest("aes128");
    }

    public void testRC2Bytes() throws Exception {
        encTest("rc2");
    }

    public void testDESBytes() throws Exception {
        encTest("des");
    }



}
