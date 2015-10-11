package com.wagmorelabs.secrets.examples;

import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.kms.AWSKMSClient;
import com.wagmorelabs.secrets.KeyManager;
import com.wagmorelabs.secrets.KmsKeyManager;
import com.wagmorelabs.secrets.Secrets;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * KmsExample demonstrates how to configure an AWS KMS client for use with Secrets.
 */
public class KmsExample {
    public static void main(String[] args) throws IOException, GeneralSecurityException {
        ProfileCredentialsProvider credentials = new ProfileCredentialsProvider("default");
        AWSKMSClient kmsClient = new AWSKMSClient(credentials);
        kmsClient.setRegion(Region.getRegion(Regions.US_WEST_1));
        KeyManager kmsKeyManager = new KmsKeyManager(kmsClient);

        Secrets secrets = new Secrets.Builder()
                .withKeyManager(kmsKeyManager)
                .build();
        secrets.readFile("secrets.yml");

        String plaintext = secrets.getString("pg_password");
        System.out.printf("%s=%s%n", "pg_password", plaintext);
    }

}
