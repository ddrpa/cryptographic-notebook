package cc.ddrpa;

import com.google.common.io.BaseEncoding;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

class HashingTests {
    private static final String PLAIN_TEXT = "Hello, world!";

    @ParameterizedTest
    @ValueSource(strings = {"SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"})
    void HashTest(String algorithm) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        byte[] hashed = digest.digest(PLAIN_TEXT.getBytes(StandardCharsets.UTF_8));
        System.out.println(algorithm + ": " + BaseEncoding.base16().lowerCase().encode(hashed));
    }
}