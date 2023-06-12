package cc.ddrpa.tink;

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.streamingaead.StreamingAeadConfig;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

class EncryptionALotDataTests {
    private static final String ASSOCIATED_DATA = """
            {
                "content-id": "1234"
            }
            """;

    @Test
    void encryptTest() throws GeneralSecurityException, IOException {
        File outputFile = File.createTempFile("", "");
        System.out.println(outputFile.getAbsolutePath());

        // Initalise Tink: register all Streaming AEAD key types with the Tink runtime
        StreamingAeadConfig.register();
        // Read the keyset into a KeysetHandle
        InputStream inputStream = this.getClass().getClassLoader().getResourceAsStream("tinkey-keyset-streaming-aead.json");
        KeysetHandle keysetHandle = CleartextKeysetHandle.read(JsonKeysetReader.withInputStream(inputStream));
        // Get the primitive
        StreamingAead streamingAead = keysetHandle.getPrimitive(StreamingAead.class);

        OutputStream ciphertextStream = streamingAead.newEncryptingStream(new FileOutputStream(outputFile), ASSOCIATED_DATA.getBytes(StandardCharsets.UTF_8));
        InputStream plaintextStream = this.getClass().getClassLoader().getResourceAsStream("nistspecialpublication800-38d.pdf");
        byte[] chunk = new byte[1024];
        int chunkLen = 0;
        while ((chunkLen = plaintextStream.read(chunk)) != -1) {
            ciphertextStream.write(chunk, 0, chunkLen);
        }
        ciphertextStream.close();
        plaintextStream.close();
    }

    @Test
    void decryptTest() throws GeneralSecurityException, IOException {
        File encryptedFile = new File("/var/folders/vm/_4w188dn0cd6q7hgt79_pvkc0000gn/T/tink16192189974274822557encrypted");
        File outputFile = File.createTempFile("", ".pdf");
        System.out.println("try: open " + outputFile.getAbsolutePath());

        // Initalise Tink: register all Streaming AEAD key types with the Tink runtime
        StreamingAeadConfig.register();
        // Read the keyset into a KeysetHandle
        InputStream inputStream = this.getClass().getClassLoader().getResourceAsStream("tinkey-keyset-streaming-aead.json");
        KeysetHandle keysetHandle = CleartextKeysetHandle.read(JsonKeysetReader.withInputStream(inputStream));
        // Get the primitive
        StreamingAead streamingAead = keysetHandle.getPrimitive(StreamingAead.class);

        InputStream ciphertextStream = streamingAead.newDecryptingStream(new FileInputStream(encryptedFile), ASSOCIATED_DATA.getBytes(StandardCharsets.UTF_8));
        OutputStream plaintextStream = new FileOutputStream(outputFile);
        byte[] chunk = new byte[1024];
        int chunkLen = 0;
        while ((chunkLen = ciphertextStream.read(chunk)) != -1) {
            plaintextStream.write(chunk, 0, chunkLen);
        }
        ciphertextStream.close();
        plaintextStream.close();
    }
}