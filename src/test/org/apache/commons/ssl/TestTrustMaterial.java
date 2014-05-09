package org.apache.commons.ssl;

import static org.apache.commons.ssl.JUnitConfig.TEST_HOME;
import org.junit.Assert;
import org.junit.Test;

public class TestTrustMaterial {

    @Test
    public void theTest() throws Exception {
        // TrustMaterial in 0.3.13 couldn't load cacerts if it contained any private keys.
        TrustMaterial tm = new TrustMaterial(TEST_HOME + "samples/cacerts-with-78-entries-and-one-private-key.jks");
        Assert.assertEquals(78, tm.getCertificates().size());
    }
    
}
