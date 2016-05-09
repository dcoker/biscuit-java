package com.wagmorelabs.biscuit;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.DecryptRequest;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * KmsKeyManager implements a KeyManager for AWS KMS.
 */
public class KmsKeyManager implements KeyManager {
    private static final Logger logger = Logger.getLogger(KmsKeyManager.class.getName());
    private static final String LABEL = "kms";
    private final AWSKMSFactory factory;
    private final String regionHint;

    /**
     * AWSKMSFactory implementations build AWSKMS clients for a particular region.
     */
    public interface AWSKMSFactory {
        AWSKMS create(String string);
    }

    /**
     * KmsKeyManager constructor.
     *
     * @param factory    The AWSKMSFactory responsible for constructing AWSKMS clients for each region. KmsKeyManager
     *                   does not cache clients and will ask the factory for clients multiple times per region, so it is
     *                   up to the caller to manage the pool of AWSKMS clients and ensure they are configured
     *                   appropriately.
     * @param regionHint The region to use when the key ID does not include a region.
     */
    public KmsKeyManager(AWSKMSFactory factory, String regionHint) {
        this.factory = factory;
        this.regionHint = regionHint;
    }

    @Override
    public byte[] decrypt(String keyID, byte[] keyCiphertext, String secretName) {
        try {
            String region = getRegionFromKeyId(keyID);
            if (null == region) {
                region = regionHint;
            }
            AWSKMS client = this.factory.create(region);
            Map<String, String> encryptionContext = new HashMap<>();
            encryptionContext.put("SecretName", secretName);
            return client.decrypt(
                    new DecryptRequest()
                            .withEncryptionContext(encryptionContext)
                            .withCiphertextBlob(ByteBuffer.wrap(keyCiphertext))
            ).getPlaintext().array();
        } catch (AmazonServiceException ex) {
            logger.log(Level.WARNING, "Exception when attempting to decrypt key", ex);
            return null;
        }
    }

    @Override
    public String label() {
        return LABEL;
    }

    /**
     * getRegionFromKeyId extracts the region from a key ARN, or returns null if not present.
     *
     * @param keyID
     * @return
     */
    static String getRegionFromKeyId(String keyID) {
        if (null == keyID) {
            return null;
        }
        keyID = keyID.trim();
        if (!keyID.startsWith("arn:")) {
            return null;
        }
        String[] split = keyID.split(":");
        if (split.length < 6) {
            return null;
        }
        return split[3];
    }
}
