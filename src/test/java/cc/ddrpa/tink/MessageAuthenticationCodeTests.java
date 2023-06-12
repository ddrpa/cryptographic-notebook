package cc.ddrpa.tink;

import com.google.common.io.BaseEncoding;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.mac.MacConfig;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

class MessageAuthenticationCodeTests {
    private static final String PLAIN_TEXT = """
            This Recommendation specifies the Galois/Counter Mode (GCM), an algorithm for\s
            authenticated encryption with associated data, and its specialization, GMAC, for generating a\s
            message authentication code (MAC) on data that is not encrypted. GCM and GMAC are modes\s
            of operation for an underlying approved symmetric key block cipher.""";

    @Test
    void computeMACTest() throws GeneralSecurityException, IOException {
        MacConfig.register();
        KeysetHandle handle = CleartextKeysetHandle.read(JsonKeysetReader.withInputStream(this.getClass().getClassLoader().getResourceAsStream("tinkey-keyset-mac.json")));
        Mac mac = handle.getPrimitive(Mac.class);
        byte[] tag = mac.computeMac(PLAIN_TEXT.getBytes());
        System.out.println("Tag: " + BaseEncoding.base16().lowerCase().encode(tag));
    }

    @Test
    void verify() throws GeneralSecurityException, IOException {
        byte[] tag = BaseEncoding.base16().lowerCase().decode("017cc68a667b5ea1c827d918357098241015b49f05");
        MacConfig.register();
        KeysetHandle handle = CleartextKeysetHandle.read(JsonKeysetReader.withInputStream(this.getClass().getClassLoader().getResourceAsStream("tinkey-keyset-mac.json")));
        Mac mac = handle.getPrimitive(Mac.class);
        mac.verifyMac(tag, PLAIN_TEXT.getBytes(StandardCharsets.UTF_8));
    }
}