package com.wagmorelabs.biscuit;

import org.junit.Test;

import javax.xml.bind.DatatypeConverter;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;

public class SecretBoxTest {
    // From https://github.com/golang/crypto/blob/master/nacl/secretbox/secretbox_test.go
    @Test
    public void golang() throws GeneralSecurityException {
        byte[] key = new byte[32];
        byte[] nonce = new byte[24];
        byte[] message = new byte[64];
        Arrays.fill(key, (byte) 1);
        Arrays.fill(nonce, (byte) 2);
        Arrays.fill(message, (byte) 3);
        byte[] result = DatatypeConverter.parseHexBinary(DatatypeConverter.printHexBinary(nonce) +
                "8442bc313f4626f1359e3b50122b6ce6fe66ddfe7d39d14e637eb4fd5" +
                "b45beadab55198df6ab5368439792a23c87db70acb6156dc5ef957ac0" +
                "4f6276cf6093b84be77ff0849cc33e34b7254d5a8f65ad");
        assertArrayEquals(message, new SecretBox().decrypt(key, result));
    }
}
