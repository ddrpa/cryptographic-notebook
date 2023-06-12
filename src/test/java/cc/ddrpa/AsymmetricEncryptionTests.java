package cc.ddrpa;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class AsymmetricEncryptionTests {
    private static final SecureRandom random = new SecureRandom();
    private static final String PLAIN_TEXT = """
            This document has been developed by the National Institute of Standards and Technology
            (NIST) in furtherance of its statutory responsibilities under the Federal Information Security
            Management Act (FISMA) of 2002, Public Law 107-347.
            NIST is responsible for developing standards and guidelines, including minimum requirements,
            for providing adequate information security for all agency operations and assets, but such
            standards and guidelines shall not apply to national security systems. This guideline is consistent
            with the requirements of the Office of Management and Budget (OMB) Circular A-130, Section
            8b(3), Securing Agency Information Systems, as analyzed in A-130, Appendix IV: Analysis of
            Key Sections. Supplemental information is provided in A-130, Appendix III.
            This Recommendation has been prepared for use by federal agencies. It may be used by
            nongovernmental organizations on a voluntary basis and is not subject to copyright. (Attribution
            would be appreciated by NIST.)
            Nothing in this document should be taken to contradict standards and guidelines made
            mandatory and binding on federal agencies by the Secretary of Commerce under statutory
            authority. Nor should these guidelines be interpreted as altering or superseding the existing
            authorities of the Secretary of Commerce, Director of the OMB, or any other federal official.
            Conformance testing for implementations of the mode of operation that is specified in this Part
            of the Recommendation will be conducted within the framework of the Cryptographic Module
            Validation Program (CMVP), a joint effort of NIST and the Communications Security
            Establishment of the Government of Canada. An implementation of a mode of operation must
            adhere to the requirements in this Recommendation in order to be validated under the CMVP.
            The requirements of this Recommendation are indicated by the word “shall.”""";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static byte[] generateRandomBytes(int lengthInBits) {
        byte[] bytes = new byte[lengthInBits / 8];
        random.nextBytes(bytes);
        return bytes;
    }

    @Test
    void generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidAlgorithmParameterException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(new ECGenParameterSpec("brainpoolP384r1"));
        KeyPair keyPair = generator.generateKeyPair();

        PublicKey publicKey = keyPair.getPublic();
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
        Base64.getEncoder().encodeToString(x509EncodedKeySpec.getEncoded());
        FileOutputStream fileOutputStream = new FileOutputStream("key.pem");
        fileOutputStream.write(x509EncodedKeySpec.getEncoded());
        fileOutputStream.close();

        PrivateKey privateKey = keyPair.getPrivate();
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        fileOutputStream = new FileOutputStream("key");
        fileOutputStream.write(pkcs8EncodedKeySpec.getEncoded());
        fileOutputStream.close();
    }

    @Test
    void ECIESWITHSHA256ANDAESCBCPlainTextTest() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(new ECGenParameterSpec("brainpoolP384r1"));
        KeyPair keyPair = generator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        System.out.println(keyPair.getPublic().getAlgorithm());
        Cipher encryptCipher = Cipher.getInstance("ECIESWITHSHA256ANDAES-CBC", BouncyCastleProvider.PROVIDER_NAME);
        Cipher decryptCipher = Cipher.getInstance("ECIESWITHSHA256ANDAES-CBC", BouncyCastleProvider.PROVIDER_NAME);
        byte[] iv = new byte[16];
        for (int i = 0; i < iv.length; i++) {
            iv[i] = (byte) 0x00;
        }
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey, new IESParameterSpec(null, null, 256, 128, iv));
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey, new IESParameterSpec(null, null, 256, 128, iv));
        byte[] plainText = PLAIN_TEXT.getBytes(StandardCharsets.UTF_8);
        byte[] cipherText = encryptCipher.doFinal(plainText);
        byte[] decryptedText = decryptCipher.doFinal(cipherText);
        assertArrayEquals(plainText, decryptedText);
        System.out.println(new String(decryptedText, StandardCharsets.UTF_8));
    }

    @Test
    void ECIESWITHSHA256ANDAESCBCFileTest() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(new ECGenParameterSpec("brainpoolP384r1"));
        KeyPair keyPair = generator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        System.out.println(keyPair.getPublic().getAlgorithm());
        Cipher encryptCipher = Cipher.getInstance("ECIESWITHSHA256ANDAES-CBC", BouncyCastleProvider.PROVIDER_NAME);
        Cipher decryptCipher = Cipher.getInstance("ECIESWITHSHA256ANDAES-CBC", BouncyCastleProvider.PROVIDER_NAME);
        byte[] iv = new byte[16];
        for (int i = 0; i < iv.length; i++) {
            iv[i] = (byte) 0x00;
        }
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey, new IESParameterSpec(null, null, 256, 128, iv));
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey, new IESParameterSpec(null, null, 256, 128, iv));
        byte[] plainText = this.getClass().getClassLoader().getResourceAsStream("nistspecialpublication800-38d.pdf").readAllBytes();
        byte[] cipherText = encryptCipher.doFinal(plainText);
        byte[] decryptedText = decryptCipher.doFinal(cipherText);
        assertArrayEquals(plainText, decryptedText);
        System.out.println(new String(decryptedText, StandardCharsets.UTF_8));
    }
}