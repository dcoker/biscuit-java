package com.wagmorelabs.secrets;

import org.junit.Test;

import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;

/**
 * Unit test for KmsKeyManager.
 */
public class KmsKeyManagerTest {

    @Test
    public void arnParse() throws GeneralSecurityException {
        Map<String, String> arns = new HashMap<>();
        arns.put("arn:aws:kms:us-west-1:123456789012:key/37793df5-ad32-4d06-b19f-bfb95cee4a35", "us-west-1");
        arns.put("key/37793df5-ad32-4d06-b19f-bfb95cee4a35", null);
        arns.put("arn:aws:kms:us-west-1:123456789012:alias/biscuit-x", "us-west-1");
        arns.put("alias/biscuit-x", null);
        for (Map.Entry<String, String> entry : arns.entrySet()) {
            assertEquals(entry.getValue(), KmsKeyManager.getRegionFromKeyId(entry.getKey()));
        }
    }
}
