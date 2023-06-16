package cc.ddrpa.tink;

import com.google.common.io.BaseEncoding;
import com.google.common.primitives.Longs;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.subtle.AesGcmJce;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;

class EncryptionSmallDataSetTests {
    private static final String PLAIN_TEXT = "Hello, world!";
    private static final byte[] associatedData = """
            {
                "content-id": "1234"
            }
            """.getBytes(StandardCharsets.UTF_8);
    private static KeysetHandle keysetHandle;

    @BeforeEach
    void register() throws GeneralSecurityException, IOException {
        // Register all AEAD key types with the Tink runtime
        AeadConfig.register();

        // Read the keyset into a KeysetHandle
        InputStream inputStream = this.getClass().getClassLoader().getResourceAsStream("tinkey-keyset-aead-aesgcm-only.json");
        keysetHandle = CleartextKeysetHandle.read(JsonKeysetReader.withInputStream(inputStream));
    }

    @Test
    void encryptTest() throws GeneralSecurityException {
        // Get the primitive
        Aead aead = keysetHandle.getPrimitive(Aead.class);

        byte[] plaintext = PLAIN_TEXT.getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = aead.encrypt(plaintext, associatedData);

        System.out.println("Ciphertext: " + BaseEncoding.base16().lowerCase().encode(ciphertext));
    }

    @Test
    void decryptTest() throws GeneralSecurityException {
        byte[] cipherText = BaseEncoding.base16().lowerCase().decode("0124916899acd80ed748581c85deb53c09732217edde8877cb5dbad21240d6b28bcf8cbe65c6f17d917527121a8c");

        // Get the primitive
        Aead aead = keysetHandle.getPrimitive(Aead.class);

        byte[] decryptedWithAssociatedData = aead.decrypt(cipherText, associatedData);
        assertEquals(PLAIN_TEXT, new String(decryptedWithAssociatedData, StandardCharsets.UTF_8));
    }

    @Test
    void shouldFailWithoutCorrectAssociatedDataTest() throws GeneralSecurityException {
        byte[] cipherText = BaseEncoding.base16().lowerCase().decode("0124916899acd80ed748581c85deb53c09732217edde8877cb5dbad21240d6b28bcf8cbe65c6f17d917527121a8c");
        // Get the primitive
        Aead aead = keysetHandle.getPrimitive(Aead.class);
        try {
            aead.decrypt(cipherText, new byte[0]);
        } catch (GeneralSecurityException e) {
            assertEquals("decryption failed", e.getMessage());
        }
    }

    /**
     * 展示通过调用内部类的方法避开密钥集的概念后通过 Tink 加密的方法
     * 适用于和第三方对接时，第三方不支持密钥集的情况
     *
     * @throws GeneralSecurityException
     */
    @Test
    void useTinkWithoutKeysetTest() throws GeneralSecurityException {
        String sharedKey = "f1f0efb6a046934dd798bc02dab7a283";

        byte[] key = BaseEncoding.base16().lowerCase().decode(sharedKey);
        System.out.println("Key: " + BaseEncoding.base16().lowerCase().encode(key));
        AesGcmJce aesGcmJce = new AesGcmJce(key);
        byte[] cipherText = aesGcmJce.encrypt(PLAIN_TEXT.getBytes(StandardCharsets.UTF_8), associatedData);
        // 密文长度等于 iv 长度 + 明文长度 + tag 长度
        assertEquals(12 + PLAIN_TEXT.getBytes(StandardCharsets.UTF_8).length + 16, cipherText.length);
        String cipherTextForTransport = BaseEncoding.base16().lowerCase().encode(cipherText);
        System.out.println("Ciphertext: " + cipherTextForTransport);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] receivedCipherText = BaseEncoding.base16().lowerCase().decode(cipherTextForTransport);
        byte[] nonce = Arrays.copyOfRange(receivedCipherText, 0, 12);
        byte[] actualCipherText = Arrays.copyOfRange(receivedCipherText, 12, receivedCipherText.length);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(BaseEncoding.base16().lowerCase().decode(sharedKey), "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(associatedData);
        byte[] decrypted = cipher.doFinal(actualCipherText);
        assertEquals(PLAIN_TEXT, new String(decrypted, StandardCharsets.UTF_8));
    }

    @Test
    void analyzeCipherTextTest() throws GeneralSecurityException, IOException {
        byte[] key = new byte[]{-15, -16, -17, -74, -96, 70, -109, 77, -41, -104, -68, 2, -38, -73, -94, -125};
        byte[] cipherText = BaseEncoding.base16().lowerCase().decode("0124916899acd80ed748581c85deb53c09732217edde8877cb5dbad21240d6b28bcf8cbe65c6f17d917527121a8c");
        System.out.println("明文长度：" + PLAIN_TEXT.getBytes(StandardCharsets.UTF_8).length);
        // 1-byte version
        // 4-byte key id
        // 12-byte nonce
        // 13-byte ciphertext same as plain text with 16-byte tag (or mac)
        assertEquals(1 + 4 + 12 + (13 + 16), cipherText.length);
        assertEquals(0x01, cipherText[0]);
        assertEquals(613509273L, Longs.fromBytes((byte) 0, (byte) 0, (byte) 0, (byte) 0, cipherText[1], cipherText[2], cipherText[3], cipherText[4]));
        byte[] nonce = new byte[12];
        System.arraycopy(cipherText, 5, nonce, 0, 12);
        System.out.println("nonce: " + BaseEncoding.base16().lowerCase().encode(nonce));
        byte[] cipherTextWithTag = new byte[13 + 16];
        System.arraycopy(cipherText, 17, cipherTextWithTag, 0, 29);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(associatedData);
        byte[] decrypted = cipher.doFinal(cipherTextWithTag);
        System.out.println("Decrypted: " + new String(decrypted, StandardCharsets.UTF_8));
    }
}