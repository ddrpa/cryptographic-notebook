package cc.ddrpa.tink;

import com.google.common.io.BaseEncoding;
import com.google.crypto.tink.*;
import com.google.crypto.tink.signature.SignatureConfig;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

public class DigitalSignatureTests {
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

    @Test
    void signTest() throws GeneralSecurityException, IOException {
        SignatureConfig.register();
        KeysetHandle handle = CleartextKeysetHandle.read(JsonKeysetReader.withInputStream(this.getClass().getClassLoader().getResourceAsStream("tinkey-keyset-signature-private.json")));
        PublicKeySign signer = handle.getPrimitive(PublicKeySign.class);

        byte[] message = PLAIN_TEXT.getBytes(StandardCharsets.UTF_8);
        byte[] signature = signer.sign(message);
        System.out.println("signature: " + BaseEncoding.base16().lowerCase().encode(signature));
    }

    @Test
    void verify() throws GeneralSecurityException, IOException {
        SignatureConfig.register();
        KeysetHandle handle = CleartextKeysetHandle.read(JsonKeysetReader.withInputStream(this.getClass().getClassLoader().getResourceAsStream("tinkey-keyset-signature-public.json")));
        PublicKeyVerify verifier = handle.getPrimitive(PublicKeyVerify.class);

        byte[] signature = BaseEncoding.base16().lowerCase().decode("010707abc83045022100dc2fa009e5f4e62f0354de359dd5da434253126df369ef684c2501939db915e4022078c029b8d2f105c58ffffddda491358c7460ee5a01ca0dd812389633dadeda02");
        verifier.verify(signature, PLAIN_TEXT.getBytes(StandardCharsets.UTF_8));
    }
}