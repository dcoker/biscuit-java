package com.wagmorelabs.secrets;

import org.junit.Test;

import java.security.GeneralSecurityException;

import static javax.xml.bind.DatatypeConverter.parseHexBinary;
import static org.junit.Assert.assertArrayEquals;

public class AesGcm256Test {

    private static final int KEY = 0;
    private static final int NONCE = 1;
    private static final int PLAINTEXT = 2;
    private static final int RESULT = 3;

    // Test vectors taken from https://golang.org/src/crypto/cipher/gcm_test.go
    private static final String[][] aesGcmTests = {
            // key, nonce, plaintext, result
            {
                    "11754cd72aec309bf52f7687212e8957",
                    "3c819d9a9bed087615030b65",
                    "",
                    "250327c674aaf477aef2675748cf6971"
            },
            {
                    "ca47248ac0b6f8372a97ac43508308ed",
                    "ffd2b598feabc9019262d2be",
                    "",
                    "60d20404af527d248d893ae495707d1a",
            },
            {
                    "7fddb57453c241d03efbed3ac44e371c",
                    "ee283a3fc75575e33efd4887",
                    "d5de42b461646c255c87bd2962d3b9a2",
                    "2ccda4a5415cb91e135c2a0f78c9b2fdb36d1df9b9d5e596f83e8b7f52971cb3",
            },
    };

    @Test
    public void testDecryption() throws GeneralSecurityException {
        for (String[] testCase : aesGcmTests) {
            byte[] key = parseHexBinary(testCase[KEY]);
            byte[] plaintext = parseHexBinary(testCase[PLAINTEXT]);
            byte[] ciphertext = parseHexBinary(testCase[RESULT] + testCase[NONCE]);
            assertArrayEquals(plaintext, new AesGcm256().decrypt(key, ciphertext));
        }
    }
}
