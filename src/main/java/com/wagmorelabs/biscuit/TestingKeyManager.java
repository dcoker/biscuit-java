package com.wagmorelabs.biscuit;

import java.util.Arrays;

/**
 * TestingKeyManager implements a key manager with a fixed key. This is only for use in tests.
 */
class TestingKeyManager implements KeyManager {
    @Override
    public byte[] decrypt(String keyID, byte[] keyCiphertext, String secretName) {
        byte[] plaintextKey = new byte[32];
        Arrays.fill(plaintextKey, (byte) 'x');
        return plaintextKey;
    }

    @Override
    public String label() {
        return "testing";
    }
}
