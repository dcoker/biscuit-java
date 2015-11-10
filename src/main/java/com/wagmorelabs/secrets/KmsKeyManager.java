package com.wagmorelabs.secrets;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.DecryptRequest;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

/**
 * KmsKeyManager implements a KeyManager for AWS KMS.
 */
public class KmsKeyManager implements KeyManager {
    private static final String LABEL = "kms";
    private final AWSKMS client;

    public KmsKeyManager(AWSKMS client) {
        this.client = client;
    }

    @Override
    public byte[] decrypt(byte[] keyCiphertext, String secretId) {
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("SecretId", secretId);
        return client.decrypt(
                new DecryptRequest()
                        .withEncryptionContext(encryptionContext)
                        .withCiphertextBlob(ByteBuffer.wrap(keyCiphertext))
        ).getPlaintext().array();
    }

    @Override
    public String label() {
        return LABEL;
    }
}
