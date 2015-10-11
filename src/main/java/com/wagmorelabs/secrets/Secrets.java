package com.wagmorelabs.secrets;

import org.yaml.snakeyaml.Yaml;

import javax.xml.bind.DatatypeConverter;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

/**
 * Secrets reads encrypted values from a file and decrypts them with the help of a key management
 * service.
 */
public class Secrets {

    private final Map<String, KeyManager> keyManagers;
    private final Map<String, Algorithm> algorithms;
    private final Map<String, Map<String, String>> values = new HashMap<>();

    /**
     * Constructor. See {@link com.wagmorelabs.secrets.Secrets.Builder}.
     *
     * @param keyManagers
     * @param algorithms
     */
    private Secrets(Map<String, KeyManager> keyManagers, Map<String, Algorithm> algorithms) {
        this.keyManagers = keyManagers;
        this.algorithms = algorithms;
    }

    private static byte[] decodeBase64(String encoded) {
        return DatatypeConverter.parseBase64Binary(encoded);
    }

    /**
     * readFile() reads a YAML document containing one or more secrets from a file.
     *
     * @param filename
     * @throws IOException
     */
    public void readFile(String filename) throws IOException {
        try (BufferedReader reader =
                     Files.newBufferedReader(Paths.get(filename), Charset.forName("UTF-8"))) {
            read(reader);
        }
    }

    /**
     * read() reads a YAML document containing one or more secrets from a Reader.
     *
     * @param reader
     */
    public void read(Reader reader) {
        Yaml yaml = new Yaml();
        @SuppressWarnings("unchecked")
        Map<String, Map<String, String>> map = (Map<String, Map<String, String>>) yaml.loadAs(reader, Map.class);
        // fill in any missing values with blanks to avoid obnoxious nullity tests later
        for (String key : map.keySet()) {
            for (Field field : Field.values()) {
                if (!map.get(key).containsKey(field.toString())) {
                    map.get(key).put(field.toString(), "");
                }
            }
        }
        values.putAll(map);
    }

    /**
     * get() returns the plaintext as a byte array. Returns null if the secret with the requested
     * name does not exist.
     *
     * @param name
     * @return
     * @throws GeneralSecurityException
     */
    public byte[] get(String name) throws GeneralSecurityException {
        Map<String, String> entry = values.get(name);
        if (entry == null) {
            // entry does not exist
            return null;
        }
        Algorithm algo = algorithms.get(Field.ALGORITHM.get(entry));
        if (null == algo) {
            throw new NoSuchAlgorithmException("Unrecognized algorithm: " +
                    Field.ALGORITHM.get(entry));
        }
        byte[] key = null;
        if (algo.requiresKey()) {
            KeyManager keyManager = keyManagers.get(Field.KEY_MANAGER.get(entry));
            if (null == keyManager) {
                throw new KeyStoreException("Unrecognized key manager: " +
                        Field.KEY_MANAGER.get(entry));
            }
            key = keyManager.decrypt(decodeBase64(Field.KEY_CIPHERTEXT.get(entry)));
        }
        String ciphertext = Field.CIPHERTEXT.get(entry);
        return algo.decrypt(key, decodeBase64(ciphertext));
    }

    /**
     * getString() returns the plaintext of the secret interpreted as a UTF-8 string.
     *
     * @param name
     * @return
     * @throws GeneralSecurityException
     */
    public String getString(String name) throws GeneralSecurityException {
        byte[] plaintext = get(name);
        if (plaintext == null) {
            return null;
        }
        return new String(plaintext, Charset.forName("UTF-8"));
    }

    private enum Field {
        KEY_ID,
        KEY_MANAGER,
        KEY_CIPHERTEXT,
        ALGORITHM,
        CIPHERTEXT;

        public String get(Map<String, String> entry) {
            return entry.get(this.name().toLowerCase());
        }

        @Override
        public String toString() {
            return this.name().toLowerCase();
        }
    }

    /**
     * Builder for the Secrets class.
     */
    public static class Builder {
        private final Map<String, KeyManager> keyManagers = new HashMap<>();
        private final Map<String, Algorithm> algorithms = new HashMap<>();

        public Builder() {
            withAlgorithm(new SecretBox());
            withAlgorithm(new AesGcm256());
            withAlgorithm(new Plaintext());
            withKeyManager(new TestingKeyManager());
        }

        /**
         * Registers an algorithm.
         *
         * @param algorithm
         * @return
         */
        public Builder withAlgorithm(Algorithm algorithm) {
            algorithms.put(algorithm.label(), algorithm);
            return this;
        }

        /**
         * Registers a key manager.
         *
         * @param keyManager
         * @return
         */
        public Builder withKeyManager(KeyManager keyManager) {
            keyManagers.put(keyManager.label(), keyManager);
            return this;
        }

        /**
         * Instantiates a configured Secrets object.
         *
         * @return
         */
        public Secrets build() {
            return new Secrets(keyManagers, algorithms);
        }
    }
}
