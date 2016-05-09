package com.wagmorelabs.biscuit;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

/**
 * AesGcm256 implements an AES-GCM-256 decryption operation compatible with Golang
 * crypto/cipher AESGCM AEAD.
 */
class AesGcm256 implements Algorithm {
    private static final int AESGCM_NONCE_LENGTH = 12;

    @Override
    public byte[] decrypt(byte[] key, byte[] ciphertext) throws GeneralSecurityException {
        // Format of ciphertext is [message][nonce]
        byte[] message = new byte[ciphertext.length - AESGCM_NONCE_LENGTH];
        System.arraycopy(ciphertext, 0, message, 0, ciphertext.length - AESGCM_NONCE_LENGTH);
        byte[] nonce = new byte[AESGCM_NONCE_LENGTH];
        System.arraycopy(ciphertext, ciphertext.length - AESGCM_NONCE_LENGTH, nonce, 0,
                AESGCM_NONCE_LENGTH);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec params = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                params, null);
        return cipher.doFinal(message);
    }

    @Override
    public String label() {
        return "aesgcm256";
    }

    @Override
    public boolean requiresKey() {
        return true;
    }
}
