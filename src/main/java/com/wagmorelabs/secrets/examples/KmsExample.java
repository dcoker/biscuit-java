package com.wagmorelabs.secrets.examples;

import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.kms.AWSKMSClient;
import com.wagmorelabs.secrets.KeyManager;
import com.wagmorelabs.secrets.KmsKeyManager;
import com.wagmorelabs.secrets.Secrets;

import javax.crypto.Cipher;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

/**
 * KmsExample demonstrates how to configure an AWS KMS client for use with Secrets.
 */
public class KmsExample {
    public static void main(String[] args) throws IOException, GeneralSecurityException {
        verifyJcePoliciesAllow256();
        java.security.Security.setProperty("networkaddress.cache.ttl", "15");

        // The profile loaded will be determined by the AWS_PROFILE environment variable, the aws.profile system
        // property, or it will be "default".
        ProfileCredentialsProvider credentials = new ProfileCredentialsProvider();

        // On EC2, you could also use EC2MetadataUtils.getRegion().
        String regionHint = System.getenv("AWS_REGION");

        KeyManager kmsKeyManager = new KmsKeyManager(region ->
                Region.getRegion(Regions.fromName(region)).createClient(AWSKMSClient.class, credentials, null),
                regionHint);

        Secrets secrets = new Secrets.Builder()
                .withKeyManager(kmsKeyManager)
                .build();
        secrets.readFile("secrets.yml");

        String secretName = "pg_password";
        String plaintext = secrets.getString(secretName);
        System.out.printf("%s=%s%n", secretName, plaintext);
    }

    private static void verifyJcePoliciesAllow256() throws NoSuchAlgorithmException {
        if (Cipher.getMaxAllowedKeyLength("AES") < 256) {
            throw new SecurityException("JCE is not configured to support 256 bit keys.");
        }
    }
}
