package com.pila.credential.vp;

import com.pila.credential.common.signer.DefaultSignerProvider;
import com.pila.credential.common.verificationmethod.DIDDocument;
import com.pila.credential.common.verificationmethod.StaticDocumentResolver;
import com.pila.credential.common.verificationmethod.VerificationMethodEntry;
import com.pila.credential.vc.CredentialConfig;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Blocking review finding: JSON-LD VP challenge/domain must be enforced against a
 * signature-verified proof (replay), and the expected* options must enable verification.
 */
public class PresentationChallengeBindingTest {

    private static final String PRIV = "2c79686425aee8002cb189bf294f2d52ca43851797c7b6e78a7dc361c4373e46";
    private static final String HOLDER = "did:example:vpholder";
    private static final String KID = HOLDER + "#key-1";

    @AfterEach
    void reset() {
        CredentialConfig.setDocumentResolver(null);
    }

    /** The expected-value and audience options must switch proof verification on (go parity). */
    @Test
    void expected_options_enable_verification() {
        assertTrue(new PresentationOptions().withExpectedChallenge("n1").isVerifyProof());
        assertTrue(new PresentationOptions().withExpectedDomain("https://verifier.example").isVerifyProof());
        assertTrue(new PresentationOptions().withRequireAudience().isVerifyProof());
    }

    /** A proof bound to challenge n1 must be rejected when a different challenge is expected. */
    @Test
    void challenge_mismatch_is_rejected() throws Exception {
        StaticDocumentResolver resolver = new StaticDocumentResolver();
        resolver.register(holderDoc());
        CredentialConfig.setDocumentResolver(resolver);

        PresentationContents vpc = new PresentationContents();
        vpc.setContext(List.of("https://www.w3.org/ns/credentials/v2"));
        vpc.setTypes(List.of("VerifiablePresentation"));
        vpc.setHolder(HOLDER);

        JSONPresentation pres = JSONPresentation.create(vpc);
        pres.addProofByProvider(new DefaultSignerProvider(PRIV),
                new PresentationOptions().withChallenge("n1").withDomain("https://verifier.example"));

        // Correct challenge + domain verify.
        pres.verify(new PresentationOptions()
                .withExpectedChallenge("n1")
                .withExpectedDomain("https://verifier.example"));

        // A replayed/forged expectation must fail.
        assertThrows(Exception.class,
                () -> pres.verify(new PresentationOptions().withExpectedChallenge("n2")));
        assertThrows(Exception.class,
                () -> pres.verify(new PresentationOptions().withExpectedDomain("https://evil.example")));
    }

    private static DIDDocument holderDoc() {
        BigInteger d = new BigInteger(1, Hex.decode(PRIV));
        ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECPoint q = spec.getG().multiply(d).normalize();
        VerificationMethodEntry vm = new VerificationMethodEntry();
        vm.setId(KID);
        vm.setType("EcdsaSecp256k1VerificationKey2019");
        vm.setController(HOLDER);
        vm.setPublicKeyHex(Hex.toHexString(q.getEncoded(false)));
        DIDDocument doc = new DIDDocument();
        doc.setId(HOLDER);
        doc.setVerificationMethod(List.of(vm));
        doc.setAssertionMethod(List.of(KID));
        doc.setAuthentication(List.of(KID));
        return doc;
    }
}
