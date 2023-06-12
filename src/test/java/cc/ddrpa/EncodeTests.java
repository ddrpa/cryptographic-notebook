package cc.ddrpa;

import com.google.common.io.BaseEncoding;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;

class EncodeTests {
    @Test
    void base64EncodeAndDecodeTest() {
        String source = "Hello, world!";
        String encoded = Base64.getEncoder().encodeToString(source.getBytes());
        System.out.println(encoded);
        String decoded = new String(Base64.getDecoder().decode(encoded));
        assertEquals(source, decoded);
    }

    @Test
    void base64URLEncodeAndDecodeTest() {
        String source = "Hello, world!";
        String encoded = Base64.getUrlEncoder().encodeToString(source.getBytes());
        System.out.println(encoded);
        String decoded = new String(Base64.getUrlDecoder().decode(encoded));
        assertEquals(source, decoded);
    }

    @Test
    void generateRandomStringTest() {
        SecureRandom random = new SecureRandom();
        byte[] buffer = new byte[16];
        random.nextBytes(buffer);
        System.out.println(BaseEncoding.base16().encode(buffer));
    }
}