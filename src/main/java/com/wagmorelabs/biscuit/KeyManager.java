package com.wagmorelabs.biscuit;

/**
 * KeyManager wraps a key management service.
 */
public interface KeyManager {
    /**
     * Decrypts an encrypted key.
     *
     * @param keyID
     * @param keyCiphertext
     * @param secretName    The name of the secret being decrypted.
     * @return
     */
    byte[] decrypt(String keyID, byte[] keyCiphertext, String secretName);

    /**
     * Returns the string used in the secret store to identify this key management service.
     *
     * @return
     */
    String label();
}
