package cc.ddrpa;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class SymmetricEncryptionWithSM4Tests {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final SecureRandom random = new SecureRandom();

    private static final String PLAIN_TEXT = """
            This Recommendation specifies the Galois/Counter Mode (GCM), an algorithm for\s
            authenticated encryption with associated data, and its specialization, GMAC, for generating a\s
            message authentication code (MAC) on data that is not encrypted. GCM and GMAC are modes\s
            of operation for an underlying approved symmetric key block cipher.""";

    private static byte[] generateRandomBytes(int lengthInBits) {
        byte[] bytes = new byte[lengthInBits / 8];
        random.nextBytes(bytes);
        return bytes;
    }

    private static final Integer GCM_IV_SIZE_IN_BITS = 96;
    private static final Integer GCM_TAG_SIZE_IN_BITS = 128;

    /**
     * 使用 SM4-GCM-NoPadding 的 AEAD 方案
     *
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    @Test
    void SM4GCMNoPaddingTest() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        // 通常情况下 key 应当秘密地获取
        byte[] key = generateRandomBytes(128);
        // nonce 不需要加密，且应当随 cipher text 一起存储
        byte[] nonce = generateRandomBytes(GCM_IV_SIZE_IN_BITS);
        byte[] plainText = PLAIN_TEXT.getBytes(StandardCharsets.UTF_8);

        Cipher cipher = Cipher.getInstance("SM4/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "SM4"), new GCMParameterSpec(GCM_TAG_SIZE_IN_BITS, nonce));
        // 有些环境不支持空的 AAD，例如 Android KitKat (API level 19)
        cipher.updateAAD(new byte[0]);
        byte[] cipherText = cipher.doFinal(plainText);

        // 输出的 cipher text 包含了 tag
        assertEquals(GCM_TAG_SIZE_IN_BITS / 8, cipherText.length - plainText.length);

        cipher = Cipher.getInstance("SM4/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "SM4"), new GCMParameterSpec(GCM_TAG_SIZE_IN_BITS, nonce));
        cipher.updateAAD(new byte[0]);
        byte[] decryptedText = cipher.doFinal(cipherText);
        assertArrayEquals(plainText, decryptedText);
    }
}