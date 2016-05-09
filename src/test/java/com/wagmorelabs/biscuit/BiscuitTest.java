package com.wagmorelabs.biscuit;

import org.junit.Test;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.*;

public class BiscuitTest {

    @Test
    public void emptyCiphertext() throws GeneralSecurityException {
        Biscuit biscuit = new Biscuit.Builder().build();
        assertNull(biscuit.get("404"));
        assertNull(biscuit.getString("404"));
        biscuit.read(new StringReader("k:\n- algorithm: none\n  ciphertext: \"\""));
        biscuit.read(new StringReader("no_ciphertext:\n- algorithm: none\n"));
        assertNull(biscuit.get("404"));
        assertNull(biscuit.getString("404"));
        assertNotNull(biscuit.get("no_ciphertext"));
        assertNotNull(biscuit.getString("no_ciphertext"));
        assertNotNull(biscuit.get("k"));
        assertNotNull(biscuit.getString("k"));
    }

    @Test
    public void missingKeys() throws GeneralSecurityException {
        Biscuit biscuit = new Biscuit.Builder().build();
        assertNull(biscuit.get("404"));
        biscuit.read(new StringReader("k:\n- algorithm: none\n  ciphertext: aGVsbG8K"));
        assertNull(biscuit.get("404"));
        assertNull(biscuit.getString("404"));
        assertNotNull(biscuit.get("k"));
        assertNotNull(biscuit.getString("k"));
    }

    @Test
    public void testUnknownAlgorithm() throws GeneralSecurityException {
        Biscuit biscuit = new Biscuit.Builder().build();
        biscuit.read(new StringReader("k:\n- algorithm: 3des\n  ciphertext: aGVsbG8K"));
        assertNull(biscuit.get("k"));
    }

    @Test
    public void testUnknownKeyManager() throws GeneralSecurityException {
        Biscuit biscuit = new Biscuit.Builder().build();
        biscuit.read(new StringReader("k:\n- key_manager: kms\n  algorithm: secretbox\n"));
        assertNull(biscuit.get("k"));
    }

    @Test
    public void secretsFromReader() throws GeneralSecurityException {
        Biscuit biscuit = new Biscuit.Builder().build();
        biscuit.read(new InputStreamReader(getClass().getResourceAsStream("secrets.yml"),
                Charset.forName("UTF-8")));
        commonTests(biscuit);
    }

    @Test
    public void secretsFromFile() throws GeneralSecurityException, IOException {
        Biscuit biscuit = new Biscuit.Builder().build();
        biscuit.readFile(getClass().getResource("secrets.yml").getFile());
        commonTests(biscuit);
    }

    @Test
    public void secretsFromJsonFile() throws GeneralSecurityException, IOException {
        Biscuit biscuit = new Biscuit.Builder().build();
        biscuit.readFile(getClass().getResource("secrets.json").getFile());
        assertEquals("v-aesgcm256", biscuit.getString("launchcodes"));
    }

    @Test
    public void verifyUnlimitedJcePolicy() throws NoSuchAlgorithmException {
        assertTrue(Cipher.getMaxAllowedKeyLength("AES") >= 256);
    }

    private void commonTests(Biscuit biscuit) throws GeneralSecurityException {
        String expectedMd5 = "748c617aaee4b9263761ed851769a314";
        for (String algo : new String[]{"none", "aesgcm256", "secretbox"}) {
            assertEquals("v-" + algo, biscuit.getString("k-" + algo));
            byte[] digest = MessageDigest.getInstance("MD5").digest(biscuit.get("k-" + algo + "-big"));
            assertArrayEquals(DatatypeConverter.parseHexBinary(expectedMd5), digest);
        }
    }
}
