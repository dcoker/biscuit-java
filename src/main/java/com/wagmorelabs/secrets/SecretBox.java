package com.wagmorelabs.secrets;

import com.emstlk.nacl4s.crypto.secretbox.XSalsa20Poly1305;

import java.security.GeneralSecurityException;

/**
 * SecretBox implements a wrapper around an implementation of a NaCl-compatible
 * secretbox_open implementation.
 */
class SecretBox implements Algorithm {
    private static final int SECRETBOX_NONCE_LENGTH = XSalsa20Poly1305.nonceBytes();

    @Override
    public byte[] decrypt(byte[] key, byte[] ciphertext) throws GeneralSecurityException {
        // Format of ciphertext is [nonce][message]
        byte[] nonce = new byte[SECRETBOX_NONCE_LENGTH];
        System.arraycopy(ciphertext, 0, nonce, 0, SECRETBOX_NONCE_LENGTH);
        byte[] message = new byte[ciphertext.length - SECRETBOX_NONCE_LENGTH];
        System.arraycopy(ciphertext, SECRETBOX_NONCE_LENGTH, message, 0,
                ciphertext.length - SECRETBOX_NONCE_LENGTH);
        com.emstlk.nacl4s.crypto.SecretBox box = new com.emstlk.nacl4s.crypto.SecretBox(key);
        return box.decrypt(nonce, message);
    }

    @Override
    public String label() {
        return "secretbox";
    }

    @Override
    public boolean requiresKey() {
        return true;
    }
}
