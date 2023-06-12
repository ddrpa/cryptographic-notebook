package cc.ddrpa;

import com.google.common.io.BaseEncoding;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

class CSPRNGTests {
    @RepeatedTest(10)
    void generateSafeRandomBytesTest() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[20];
        random.nextBytes(bytes);
        System.out.println(BaseEncoding.base16().lowerCase().encode(bytes));
        System.out.println(random.nextBoolean());
        System.out.println(random.nextInt());
        System.out.println(random.nextInt(10));
        System.out.println(random.nextGaussian());
    }

    @Test
    void checkProviderAndAlgorithmTest() {
        SecureRandom random = new SecureRandom();
        System.out.println(random.getProvider().getName());
        System.out.println(random.getAlgorithm());
    }
}