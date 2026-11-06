package com.pila.credential.vp;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.dto.Proof;
import com.pila.credential.common.error.AudienceUnboundException;
import com.pila.credential.common.error.CredentialException;
import com.pila.credential.common.error.CredentialException.Code;
import com.pila.credential.common.signer.DefaultSignerProvider;
import com.pila.credential.common.signer.P256SignerProvider;
import com.pila.credential.common.verificationmethod.StaticDocumentResolver;
import com.pila.credential.vc.CredentialOptions;
import com.pila.credential.vc.JOSECredential;
import com.pila.credential.vc.JSONCredential;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static com.pila.credential.vc.ParityFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

/** Mirrors go-credential-sdk credential/vp behaviour (JSON-LD, VP-JWT, vp+jwt, options, routing). */
public class VpGoParityTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String HOLDER = "did:example:holder";
    private static final String ISSUER = "did:example:issuer";

    private static PresentationContents vpc(String holder, boolean v2) {
        PresentationContents c = new PresentationContents();
        c.setContext(List.of(v2 ? "https://www.w3.org/ns/credentials/v2" : "https://www.w3.org/2018/credentials/v1"));
        c.setTypes(List.of("VerifiablePresentation"));
        c.setHolder(holder);
        return c;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> claims(String jwt) throws Exception {
        return MAPPER.readValue(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), Map.class);
    }

    // ---- JWT VP: resolver injection, alg from VM, nonce/aud only when set, sign-time challenge ----------------

    @Test
    void jwtVp_p256Holder_injectedResolver_noEmptyClaims_signTimeChallenge_externalSigning() throws Exception {
        StaticDocumentResolver r = resolver(p256Doc(HOLDER));
        PresentationOptions opts = new PresentationOptions().withResolver(r);
        JWTPresentation vp = JWTPresentation.create(vpc(HOLDER, false), opts);
        assertTrue(new String(Base64.getUrlDecoder().decode(vp.serialize().split("\\.")[0])).contains("\"ES256\""));
        assertFalse(claims(vp.serialize()).containsKey("nonce"), "empty challenge is not written");
        assertFalse(claims(vp.serialize()).containsKey("aud"));

        // external signing of the signing input (3.34), nonce/aud refused there
        byte[] input = vp.getSigningInput();
        byte[] sig = new P256SignerProvider(P256_PRIV).sign(MessageDigest.getInstance("SHA-256").digest(input));
        Proof proof = new Proof();
        proof.setSignature(sig);
        assertEquals(Code.UNSUPPORTED_OPTION, assertThrows(CredentialException.class,
                () -> vp.addCustomProof(proof, new PresentationOptions().withResolver(r).withChallenge("n"))).getCode());
        vp.addCustomProof(proof, opts);
        vp.verify(opts);

        // re-signing replaces the signature: refused unless withReplaceProof; challenge/domain go in at sign time
        assertEquals(Code.ALREADY_SIGNED, assertThrows(CredentialException.class,
                () -> vp.addProofByProvider(new P256SignerProvider(P256_PRIV), opts)).getCode());
        PresentationOptions bind = new PresentationOptions().withResolver(r).withReplaceProof()
                .withChallenge("n1").withDomain("https://verifier.example");
        vp.addProofByProvider(new P256SignerProvider(P256_PRIV), bind);
        assertEquals("n1", claims(vp.serialize()).get("nonce"));
        vp.verify(new PresentationOptions().withResolver(r).withExpectedChallenge("n1")
                .withExpectedDomain("https://verifier.example"));
        assertThrows(Exception.class, () -> vp.verify(new PresentationOptions().withResolver(r)
                .withExpectedDomain("https://other.example")));

        // WithRequireAudience without WithExpectedDomain is a typed refusal
        assertThrows(AudienceUnboundException.class,
                () -> vp.verify(new PresentationOptions().withResolver(r).withRequireAudience()));

        // a signature by another key fails at signing, leaving the claims as they were
        StaticDocumentResolver r2 = resolver(secpDoc(HOLDER));
        JWTPresentation other = JWTPresentation.create(vpc(HOLDER, false), new PresentationOptions().withResolver(r2));
        assertThrows(Exception.class, () -> other.addProofByProvider(new P256SignerProvider(P256_PRIV),
                new PresentationOptions().withResolver(r2).withChallenge("x")));
        assertFalse(claims(other.serialize()).containsKey("nonce"));
    }

    @Test
    void jwtVp_checkExpirationCoversNbfAndExp() throws Exception {
        StaticDocumentResolver r = resolver(secpDoc(HOLDER));
        PresentationOptions opts = new PresentationOptions().withResolver(r);
        PresentationContents c = vpc(HOLDER, false);
        c.setValidFrom(Instant.now().plusSeconds(3600));
        JWTPresentation vp = JWTPresentation.create(c, opts);
        vp.addProofByProvider(new DefaultSignerProvider(SECP_PRIV), opts);
        String token = vp.serialize();
        assertEquals(Code.NOT_VALID_YET, assertThrows(CredentialException.class,
                () -> JWTPresentation.parse(token, new PresentationOptions().withCheckExpiration())).getCode());
        JWTPresentation.parse(token, new PresentationOptions().withCheckExpiration().withLeewayMs(2 * 3600_000L));
    }

    // ---- JSON VP ------------------------------------------------------------------------------------------------

    @Test
    void jsonVp_signingInputIsLibraryDigest_signTimeOptionsAndHolderObject() throws Exception {
        StaticDocumentResolver r = resolver(p256Doc(HOLDER));
        PresentationOptions opts = new PresentationOptions().withResolver(r);
        JSONPresentation vp = JSONPresentation.create(vpc(HOLDER, true), opts);
        assertArrayEquals(vp.getPresentationData().getDocumentDigest(), vp.getSigningInput());
        assertEquals(32, vp.getSigningInput().length);

        // verify-only expected* options (which imply proof verification) do not break signing an unsigned VP
        vp.addProof(P256_PRIV, new PresentationOptions().withResolver(r).withExpectedChallenge("n1")
                .withChallenge("n1").withDomain("https://verifier.example"));
        vp.verify(new PresentationOptions().withResolver(r).withExpectedChallenge("n1")
                .withExpectedDomain("https://verifier.example").withRequireAudience());
        assertEquals("JSON", vp.getType());
        assertNotNull(vp.extractField("proof.proofValue"));

        assertThrows(AudienceUnboundException.class,
                () -> vp.verify(new PresentationOptions().withResolver(r).withRequireAudience()));
        assertEquals(Code.UNSUPPORTED_OPTION, assertThrows(CredentialException.class,
                () -> vp.addProof(P256_PRIV, opts.copy().withReplaceProof())).getCode());

        // holder written as {"id": "..."} is accepted
        String json = "{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],\"type\":[\"VerifiablePresentation\"],"
                + "\"holder\":{\"id\":\"" + HOLDER + "\"}}";
        JSONPresentation obj = JSONPresentation.parse(json.getBytes(StandardCharsets.UTF_8));
        obj.addProof(P256_PRIV, opts);
        obj.verify(opts);
    }

    // ---- embedded credentials: single object, absent, tampered ---------------------------------------------------

    @Test
    void withVCValidation_acceptsSingleObject_failsOnAbsentOrTampered() throws Exception {
        StaticDocumentResolver r = resolver(p256Doc(ISSUER), p256Doc(HOLDER));
        PresentationOptions opts = new PresentationOptions().withResolver(r);
        JSONCredential vc = JSONCredential.newJSONCredential(contents(ISSUER), new CredentialOptions().withResolver(r));
        vc.addProof(P256_PRIV, new CredentialOptions().withResolver(r));

        PresentationContents c = vpc(HOLDER, true);
        c.setVerifiableCredentials(List.of(vc));
        JSONPresentation vp = JSONPresentation.create(c, opts);
        vp.addProof(P256_PRIV, opts);
        Map<String, Object> m = vp.serialize();

        // single object instead of an array
        Object only = ((List<?>) m.get("verifiableCredential")).get(0);
        m.put("verifiableCredential", only);
        JSONPresentation.parse(MAPPER.writeValueAsBytes(m), new PresentationOptions().withResolver(r).withVCValidation());

        // tampered embedded credential
        Map<String, Object> tampered = new java.util.HashMap<>((Map<String, Object>) only);
        ((Map<String, Object>) tampered.get("credentialSubject")).put("name", "Mallory");
        m.put("verifiableCredential", tampered);
        assertThrows(Exception.class, () -> JSONPresentation.parse(MAPPER.writeValueAsBytes(m),
                new PresentationOptions().withResolver(r).withVCValidation()));

        // no credentials at all while validation is requested
        m.remove("verifiableCredential");
        assertThrows(Exception.class, () -> JSONPresentation.parse(MAPPER.writeValueAsBytes(m),
                new PresentationOptions().withResolver(r).withVCValidation()));
    }

    // ---- JOSE VP + ParsePresentation routing ----------------------------------------------------------------------

    @Test
    void joseVp_roundTrip_routing_enveloped_andRefusals() throws Exception {
        StaticDocumentResolver r = resolver(secpDoc(ISSUER), secpDoc(HOLDER));
        CredentialOptions vcOpts = new CredentialOptions().withResolver(r);
        JOSECredential vc = JOSECredential.create(contents(ISSUER), vcOpts);
        vc.addProofByProvider(new DefaultSignerProvider(SECP_PRIV), vcOpts);

        PresentationContents c = vpc(HOLDER, true);
        c.setVerifiableCredentials(List.of(vc));
        PresentationOptions opts = new PresentationOptions().withResolver(r);
        JOSEPresentation vp = JOSEPresentation.create(c, opts.copy().withChallenge("n1")
                .withDomain("https://verifier.example"));
        vp.addProofByProvider(new DefaultSignerProvider(SECP_PRIV), opts);
        String token = vp.serialize();
        assertEquals("JOSE", vp.getType());
        assertEquals(64, vp.hash().length());

        Presentation parsed = PresentationParser.parsePresentation(token.getBytes(StandardCharsets.UTF_8),
                opts.copy().withVCValidation().withExpectedChallenge("n1")
                        .withExpectedDomain("https://verifier.example"));
        assertInstanceOf(JOSEPresentation.class, parsed);
        parsed.verify(opts);
        assertThrows(Exception.class, () -> parsed.verify(opts.copy().withExpectedChallenge("zzz")));
        assertThrows(AudienceUnboundException.class, () -> parsed.verify(opts.copy().withRequireAudience()));

        // routing: a VC 1.1 JWT presentation goes to JWTPresentation, JSON to JSONPresentation
        JWTPresentation jwt = JWTPresentation.create(vpc(HOLDER, false), opts);
        jwt.addProofByProvider(new DefaultSignerProvider(SECP_PRIV), opts);
        assertInstanceOf(JWTPresentation.class, PresentationParser.parsePresentation(
                jwt.serialize().getBytes(StandardCharsets.UTF_8)));

        // a SD-JWT shaped token and garbage are refused with their own messages
        Exception sd = assertThrows(Exception.class, () -> PresentationParser.parsePresentation(
                (token + "~abc~").getBytes(StandardCharsets.UTF_8)));
        assertTrue(sd.getMessage().contains("SD-JWT"), sd.getMessage());
        assertThrows(Exception.class, () -> PresentationParser.parsePresentation("nonsense".getBytes(StandardCharsets.UTF_8)));

        // non-enveloping credential types cannot go in a vp+jwt
        JSONCredential json = JSONCredential.newJSONCredential(contents(ISSUER));
        PresentationContents bad = vpc(HOLDER, true);
        bad.setVerifiableCredentials(List.of(json));
        assertThrows(Exception.class, () -> JOSEPresentation.create(bad, opts));

        // a bare credential inside a vp+jwt payload is refused on parse
        String[] t = token.split("\\.");
        Map<String, Object> payload = claims(token);
        payload.put("verifiableCredential", List.of("eyJ.bare.vc"));
        String forged = t[0] + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(
                MAPPER.writeValueAsBytes(payload)) + "." + t[2];
        assertThrows(Exception.class, () -> JOSEPresentation.parse(forged));
    }
}
