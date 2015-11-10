package com.wagmorelabs.secrets;

/**
 * KeyManager wraps a key management service.
 */
public interface KeyManager {
    /**
     * Decrypts an encrypted key. We assume the key manager can identify which key is in use by
     * information already embedded in the keyCiphertext.
     *
     * @param keyCiphertext
     * @param secretId The name of the secret being decrypted.
     * @return
     */
    byte[] decrypt(byte[] keyCiphertext, String secretId);

    /**
     * Returns the string used in the secret store to identify this key management service.
     *
     * @return
     */
    String label();
}
