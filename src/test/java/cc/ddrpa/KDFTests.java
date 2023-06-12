package cc.ddrpa;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertTrue;

class KDFTests {
    private static final String SUPER_SECRET_PASSWORD_EYES_ONLY = "admin";

    @Test
    void Argon2Test() {
        Argon2PasswordEncoder encoder = new Argon2PasswordEncoder(16, 32, 1, 1 << 14, 2);
        String encoded = encoder.encode(SUPER_SECRET_PASSWORD_EYES_ONLY);
        System.out.println(encoded);
        assertTrue(encoder.matches(SUPER_SECRET_PASSWORD_EYES_ONLY, encoded));
    }

    @Test
    void ScryptTest() {
        SCryptPasswordEncoder encoder = new SCryptPasswordEncoder(65536, 8, 1, 32, 16);
        String encoded = encoder.encode(SUPER_SECRET_PASSWORD_EYES_ONLY);
        System.out.println(encoded);
        assertTrue(encoder.matches(SUPER_SECRET_PASSWORD_EYES_ONLY, encoded));
    }

    @Test
    void BcryptTest() {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String encoded = encoder.encode(SUPER_SECRET_PASSWORD_EYES_ONLY);
        System.out.println(encoded);
        assertTrue(encoder.matches(SUPER_SECRET_PASSWORD_EYES_ONLY, encoded));
    }
}