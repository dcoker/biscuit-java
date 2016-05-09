package com.wagmorelabs.biscuit;

import java.security.GeneralSecurityException;

/**
 * Plaintext implements a no-op identity algorithm.
 */
class Plaintext implements Algorithm {
    @Override
    public byte[] decrypt(byte[] key, byte[] ciphertext) throws GeneralSecurityException {
        return ciphertext;
    }

    @Override
    public String label() {
        return "none";
    }

    @Override
    public boolean requiresKey() {
        return false;
    }
}
