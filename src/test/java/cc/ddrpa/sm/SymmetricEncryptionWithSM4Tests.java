package cc.ddrpa.sm;

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

/**
 * GB/T 32907-2016 信息安全技术 SM4 分组密码算法
 * https://std.samr.gov.cn/gb/search/gbDetailed?id=71F772D81199D3A7E05397BE0A0AB82A
 * <p>
 * SM4 密码算法是一个分组算法。该算法的分组长度为 128 比特,密钥长度为 128 比特。加密算法与密钥扩展算法均采用非线性迭代结构，
 * 运算轮数均为 32 轮。数据解密和数据加密的算法结构相同，只是轮密钥的使用顺序相反,解密轮密钥是加密轮密钥的逆序。
 */
class SymmetricEncryptionWithSM4Tests {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final SecureRandom random = new SecureRandom();

    private static final String PLAIN_TEXT = "SM4 密码算法是一个分组算法。该算法的分组长度为 128 比特,密钥长度为 128 比特。加密算法与密钥扩展算法均采用非线性迭代结构，运算轮数均为 32 轮。数据解密和数据加密的算法结构相同，只是轮密钥的使用顺序相反,解密轮密钥是加密轮密钥的逆序。";

    private static byte[] generateRandomBytes(int lengthInBits) {
        byte[] bytes = new byte[lengthInBits / 8];
        random.nextBytes(bytes);
        return bytes;
    }

    private static final Integer SM4_KEY_SIZE_IN_BITS = 128;
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
        byte[] key = generateRandomBytes(SM4_KEY_SIZE_IN_BITS);
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