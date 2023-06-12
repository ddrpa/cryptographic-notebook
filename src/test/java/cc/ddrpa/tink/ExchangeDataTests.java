package cc.ddrpa.tink;

import com.google.common.io.BaseEncoding;
import com.google.crypto.tink.*;
import com.google.crypto.tink.hybrid.HybridConfig;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ExchangeDataTests {
    private static final String PLAIN_TEXT = "Hello, world!";
    private static final String ASSOCIATED_DATA = """
            {
                "content-id": "1234"
            }
            """;

    @Test
    void encryptWithPublicKeyTest() throws GeneralSecurityException, IOException {
        // Register all hybrid encryption key types with the Tink runtime.
        HybridConfig.register();
        // Read the keyset into a KeysetHandle.
        KeysetHandle handle = CleartextKeysetHandle.read(JsonKeysetReader.withInputStream(this.getClass().getClassLoader().getResourceAsStream("tinkey-keyset-data-exchange-public.json")));
        // Get the primitive.
        HybridEncrypt encryptor = handle.getPrimitive(HybridEncrypt.class);
        byte[] ciphertext = encryptor.encrypt(PLAIN_TEXT.getBytes(StandardCharsets.UTF_8), ASSOCIATED_DATA.getBytes(StandardCharsets.UTF_8));
        System.out.println("Ciphertext: " + BaseEncoding.base16().lowerCase().encode(ciphertext));
    }

    @Test
    void decryptWithPrivateKeyTest() throws GeneralSecurityException, IOException {
        byte[] cipherText = BaseEncoding.base16().lowerCase().decode("012ff24f0d04a572b86a39d34f49a16cf4ae9c5962f5da7d2d933cdd2b486050c47ec41f4e1ee390430b12f9315855874f56c17ae589c958f91caeff0634d195ae5f296fc3e5a57397965d9ef17700000b86f88bf5aff164b1e7be0e98218406e7dad8");

        // Register all hybrid encryption key types with the Tink runtime.
        HybridConfig.register();
        // Read the keyset into a KeysetHandle.
        KeysetHandle handle = CleartextKeysetHandle.read(JsonKeysetReader.withInputStream(this.getClass().getClassLoader().getResourceAsStream("tinkey-keyset-data-exchange-private.json")));
        // Get the primitive
        HybridDecrypt decryptor = handle.getPrimitive(HybridDecrypt.class);
        byte[] decrypted = decryptor.decrypt(cipherText, ASSOCIATED_DATA.getBytes(StandardCharsets.UTF_8));
        assertEquals(PLAIN_TEXT, new String(decrypted, StandardCharsets.UTF_8));
    }
}
