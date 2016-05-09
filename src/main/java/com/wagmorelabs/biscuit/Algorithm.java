package com.wagmorelabs.biscuit;

import java.security.GeneralSecurityException;

interface Algorithm {
    /**
     * Decrypts a ciphertext using a given key.
     *
     * @param key
     * @param ciphertext
     * @return
     * @throws GeneralSecurityException
     */
    byte[] decrypt(byte[] key, byte[] ciphertext) throws GeneralSecurityException;

    /**
     * Returns the string used in the secret store to identify this algorithm.
     *
     * @return
     */
    String label();

    /**
     * Indicates whether or not this algorithm requires a key management service.
     *
     * @return
     */
    boolean requiresKey();
}
