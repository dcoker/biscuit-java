package com.wagmorelabs.secrets;

import org.junit.Assert;
import org.junit.Test;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class SecretsTests {

    @Test
    public void emptyCiphertext() throws GeneralSecurityException {
        Secrets secrets = new Secrets.Builder().build();
        Assert.assertNull(secrets.get("404"));
        Assert.assertNull(secrets.getString("404"));
        secrets.read(new StringReader("k:\n  algorithm: none\n  ciphertext: \"\""));
        secrets.read(new StringReader("no_ciphertext:\n  algorithm: none\n"));
        Assert.assertNull(secrets.get("404"));
        Assert.assertNull(secrets.getString("404"));
        Assert.assertNotNull(secrets.get("no_ciphertext"));
        Assert.assertNotNull(secrets.getString("no_ciphertext"));
        Assert.assertNotNull(secrets.get("k"));
        Assert.assertNotNull(secrets.getString("k"));
    }

    @Test
    public void missingKeys() throws GeneralSecurityException {
        Secrets secrets = new Secrets.Builder().build();
        Assert.assertNull(secrets.get("404"));
        secrets.read(new StringReader("k:\n  algorithm: none\n  ciphertext: aGVsbG8K"));
        Assert.assertNull(secrets.get("404"));
        Assert.assertNull(secrets.getString("404"));
        Assert.assertNotNull(secrets.get("k"));
        Assert.assertNotNull(secrets.getString("k"));
    }

    @Test(expected = NoSuchAlgorithmException.class)
    public void testUnknownAlgorithm() throws GeneralSecurityException {
        Secrets secrets = new Secrets.Builder().build();
        secrets.read(new StringReader("k:\n  algorithm: 3des\n  ciphertext: aGVsbG8K"));
        Assert.assertNull(secrets.get("k"));
    }

    @Test(expected = KeyStoreException.class)
    public void testUnknownKeyManager() throws GeneralSecurityException {
        Secrets secrets = new Secrets.Builder().build();
        secrets.read(new StringReader("k:\n  key_manager: kms\n  algorithm: secretbox\n"));
        secrets.get("k");
    }

    @Test
    public void secretsFromReader() throws GeneralSecurityException {
        Secrets secrets = new Secrets.Builder().build();
        secrets.read(new InputStreamReader(getClass().getResourceAsStream("secrets.yml"),
                Charset.forName("UTF-8")));
        commonTests(secrets);
    }

    @Test
    public void secretsFromFile() throws GeneralSecurityException, IOException {
        Secrets secrets = new Secrets.Builder().build();
        secrets.readFile(getClass().getResource("secrets.yml").getFile());
        commonTests(secrets);
    }

    @Test
    public void secretsFromJsonFile() throws GeneralSecurityException, IOException {
        Secrets secrets = new Secrets.Builder().build();
        secrets.readFile(getClass().getResource("secrets.json").getFile());
        assertEquals("v-aesgcm256", secrets.getString("launchcodes"));
    }

    private void commonTests(Secrets secrets) throws GeneralSecurityException {
        String expectedMd5 = "748c617aaee4b9263761ed851769a314";
        for (String algo : new String[]{"none", "aesgcm256", "secretbox"}) {
            assertEquals("v-" + algo, secrets.getString("k-" + algo));
            byte[] digest = MessageDigest.getInstance("MD5").digest(secrets.get("k-" + algo + "-big"));
            assertArrayEquals(DatatypeConverter.parseHexBinary(expectedMd5), digest);
        }
    }
}
