package cc.ddrpa;

import com.google.common.io.BaseEncoding;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class SymmetricEncryptionTests {
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

    private static final Integer AES_GCM_IV_SIZE_IN_BITS = 96;
    private static final Integer AES_GCM_TAG_SIZE_IN_BITS = 128;

    /**
     * 使用 AES-GCM-NoPadding 的 AEAD 方案
     *
     * @param keySize
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    @ParameterizedTest
    @ValueSource(ints = {128, 192, 256})
    void AESGCMNoPaddingTest(int keySize) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        System.out.println("Encrypting with AES-" + keySize + "-GCM-NoPadding");
        // 通常情况下 key 应当秘密地获取
        // 或是通过 Argon2 等 KDF 从口令（和其他参数）生成
        byte[] key = generateRandomBytes(keySize);
        // nonce 不需要加密，且应当随 cipher text 一起存储
        byte[] nonce = generateRandomBytes(AES_GCM_IV_SIZE_IN_BITS);
        byte[] plainText = PLAIN_TEXT.getBytes(StandardCharsets.UTF_8);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(AES_GCM_TAG_SIZE_IN_BITS, nonce));
        // 有些环境不支持空的 AAD，例如 Android KitKat (API level 19)
        cipher.updateAAD(new byte[0]);
        byte[] cipherText = cipher.doFinal(plainText);
        // 输出的 cipher text 包含了 tag
        assertEquals(AES_GCM_TAG_SIZE_IN_BITS / 8, cipherText.length - plainText.length);

        cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(AES_GCM_TAG_SIZE_IN_BITS, nonce));
        cipher.updateAAD(new byte[0]);
        byte[] decryptedText = cipher.doFinal(cipherText);
        assertArrayEquals(plainText, decryptedText);
    }

    /**
     * AES-CTR-NoPadding 不保证加密的完整性
     *
     * @param modifyCipherText
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void CTRModeDoNotEnsureAuthenticatedEncryptionTest(boolean modifyCipherText) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        if (modifyCipherText) {
            System.out.println("Encrypting with AES-128-CTR-NoPadding and modifying cipher text");
        } else {
            System.out.println("Encrypting with AES-128-CTR-NoPadding");
        }

        byte[] key = generateRandomBytes(128);
        byte[] iv = generateRandomBytes(128);
        byte[] plainText = PLAIN_TEXT.getBytes(StandardCharsets.UTF_8);

        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] cipherText = cipher.doFinal(plainText);

        if (modifyCipherText) {
            // 修改密文中的五个字节
            for (int i = 5; i < 10; i++) {
                cipherText[i] = (byte) (cipherText[i] + 1);
            }
        }

        cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));

        byte[] decryptedText = cipher.doFinal(cipherText);
        System.out.print("Decrypted text: ");
        System.out.println(new String(decryptedText, StandardCharsets.UTF_8));
        if (modifyCipherText) {
            assertFalse(Arrays.equals(plainText, decryptedText));
        } else {
            assertArrayEquals(plainText, decryptedText);
        }
    }

    /**
     * AES-GCM-NoPadding 保证加密的完整性
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    @Test
    void GCMModeEnsureAuthenticatedEncryptionTest() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] key = generateRandomBytes(128);
        byte[] iv = generateRandomBytes(128);
        byte[] plainText = PLAIN_TEXT.getBytes(StandardCharsets.UTF_8);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        byte[] cipherText = cipher.doFinal(plainText);

        // modify 5 bytes in the cipher text
        for (int i = 5; i < 10; i++) {
            cipherText[i] = (byte) (cipherText[i] + 1);
        }

        cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        try {
            byte[] decryptedText = cipher.doFinal(cipherText);
            System.out.println(new String(decryptedText, StandardCharsets.UTF_8));
        } catch (AEADBadTagException e) {
            System.out.println("AEADBadTagException");
            System.out.println(e.getMessage());
        }
    }

    /**
     * 与在线工具相互验证
     *
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    @Test
    void verifyWithOnlineTools() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        // 与 https://www.lddgo.net/en/encrypt/aes 工具相互验证
        // 还有一些在线 AES 工具没有提供 IV 输入与 KDF 选择，无法验证
        // 该工具要求 key 和 IV 以字符串形式输入，在计算过程中按选定的 Charset 转换为 byte[]
        byte[] key = "shouldhave32charshouldhave32char".getBytes(StandardCharsets.UTF_8);
        assertEquals(256 / 8, key.length);
        System.out.println("Key: shouldhave32charshouldhave32char");
        byte[] iv = "shouldhave12".getBytes(StandardCharsets.UTF_8);
        assertEquals(96 / 8, iv.length);
        System.out.println("IV: shouldhave16char");

        byte[] plainText = PLAIN_TEXT.getBytes(StandardCharsets.UTF_8);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        System.out.println("Tag value: 128");
        byte[] cipherText = cipher.doFinal(plainText);

        System.out.print("Cipher text(as hex string): ");
        System.out.println(BaseEncoding.base16().lowerCase().encode(cipherText));
    }
}
