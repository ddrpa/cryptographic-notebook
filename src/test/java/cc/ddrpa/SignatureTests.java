package cc.ddrpa;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignatureTests {
    @Test
    void SignatureTest() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException, IOException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair keyPair = generator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        Signature signSignature = Signature.getInstance("SHA256withECDSA");
        signSignature.initSign(privateKey);
        byte[] document = this.getClass().getClassLoader().getResourceAsStream("nistspecialpublication800-38d.pdf").readAllBytes();
        signSignature.update(document);
        byte[] signed = signSignature.sign();

        Signature verifySignature = Signature.getInstance("SHA256withECDSA");
        verifySignature.initVerify(publicKey);
        verifySignature.update(document);
        assertTrue(verifySignature.verify(signed));

        // modify it
        for (int i = 20; i < 30; i++) {
            signed[i] = (byte) (signed[i] - 1);
        }
        verifySignature.initVerify(publicKey);
        verifySignature.update(document);
        assertFalse(verifySignature.verify(signed));
    }
}