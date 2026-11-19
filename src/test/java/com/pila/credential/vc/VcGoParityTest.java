package com.pila.credential.vc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.credentialstatus.CredentialStatus;
import com.pila.credential.common.dto.Proof;
import com.pila.credential.common.error.CredentialException;
import com.pila.credential.common.error.CredentialException.Code;
import com.pila.credential.common.error.SDJWTRequiresJOSEException;
import com.pila.credential.common.signer.DefaultSignerProvider;
import com.pila.credential.common.signer.P256SignerProvider;
import com.pila.credential.common.signer.SignerProvider;
import com.pila.credential.common.util.Multibase;
import com.pila.credential.common.verificationmethod.StaticDocumentResolver;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPOutputStream;

import static com.pila.credential.vc.ParityFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

/** Mirrors go-credential-sdk credential/vc behaviour (signing, options, SD-JWT refusal, status, schema). */
public class VcGoParityTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String ISSUER = "did:example:issuer";

    private static CredentialOptions p256(StaticDocumentResolver r) {
        return new CredentialOptions().withResolver(r);
    }

    // ---- 3.15 / 3.16 / 6.5: alg and kid from the resolved VM, resolver per call -------------------------------

    @Test
    void jwtVc_p256Issuer_getsEs256AndKidFromInjectedResolver() throws Exception {
        StaticDocumentResolver r = resolver(p256Doc(ISSUER));
        CredentialOptions opts = p256(r);
        JWTCredential c = JWTCredential.newJWTCredential(contentsV1(ISSUER), opts);
        String header = new String(Base64.getUrlDecoder().decode(((String) c.serialize()).split("\\.")[0]));
        assertTrue(header.contains("\"alg\":\"ES256\""), header);
        assertTrue(header.contains("\"kid\":\"" + ISSUER + "#key-1\""), header);

        c.addProofByProvider(new P256SignerProvider(P256_PRIV), opts);
        c.verify(opts); // no global resolver anywhere
        assertEquals(64, c.hash().length());
        assertEquals("Alice", c.extractField("credentialSubject.name"));
        assertNull(c.extractField("credentialSubject.missing"));
    }

    @Test
    void jwtVc_secp256k1Issuer_getsEs256k_andWrongKeyIsRefusedAtSigning() throws Exception {
        StaticDocumentResolver r = resolver(secpDoc(ISSUER));
        CredentialOptions opts = p256(r);
        JWTCredential c = JWTCredential.newJWTCredential(contentsV1(ISSUER), opts);
        assertTrue(new String(Base64.getUrlDecoder().decode(((String) c.serialize()).split("\\.")[0]))
                .contains("ES256K"));
        // a signer that does not hold the VM key is caught at signing, not at the verifier
        assertThrows(Exception.class, () -> c.addProofByProvider(
                new DefaultSignerProvider("1111111111111111111111111111111111111111111111111111111111111111"), opts));
        assertEquals(2, ((String) c.serialize()).split("\\.").length, "failed signing leaves it unsigned");
        c.addProofByProvider(new DefaultSignerProvider(SECP_PRIV), opts);
        c.verify(opts);
    }

    // ---- 3.20 / 3.22: refuse overwrite, build-time options at signing ----------------------------------------

    @Test
    void jwtVc_resignRefusedUnlessReplace_andBuildTimeOptionsRefused() throws Exception {
        StaticDocumentResolver r = resolver(secpDoc(ISSUER));
        CredentialOptions opts = p256(r);
        JWTCredential c = JWTCredential.newJWTCredential(contentsV1(ISSUER), opts);
        SignerProvider signer = new DefaultSignerProvider(SECP_PRIV);
        c.addProofByProvider(signer, opts);

        CredentialException ex = assertThrows(CredentialException.class, () -> c.addProofByProvider(signer, opts));
        assertEquals(Code.ALREADY_SIGNED, ex.getCode());
        c.addProofByProvider(signer, p256(r).withReplaceProof());

        CredentialOptions withKid = p256(r).withReplaceProof().withVerificationMethodKey("key-1");
        assertEquals(Code.UNSUPPORTED_OPTION,
                assertThrows(CredentialException.class, () -> c.addProofByProvider(signer, withKid)).getCode());
        CredentialOptions withSd = p256(r).withReplaceProof().withSDShuffle(true);
        assertEquals(Code.UNSUPPORTED_OPTION,
                assertThrows(CredentialException.class, () -> c.addProofByProvider(signer, withSd)).getCode());
    }

    // ---- 1.7 / 1.9 / 4.5: VC 1.1 JWT refuses SD-JWT ----------------------------------------------------------

    @Test
    void jwtVc_refusesSelectiveDisclosure() throws Exception {
        StaticDocumentResolver r = resolver(secpDoc(ISSUER));
        assertThrows(SDJWTRequiresJOSEException.class, () -> JWTCredential.newJWTCredential(
                contentsV1(ISSUER), p256(r).withSDSelectivePaths(List.of("credentialSubject.name"))));

        JWTCredential good = JWTCredential.newJWTCredential(contentsV1(ISSUER), p256(r));
        good.addProofByProvider(new DefaultSignerProvider(SECP_PRIV), p256(r));
        String token = (String) good.serialize();

        // combined "~" form, even a plain JWT with a "~" appended
        SDJWTRequiresJOSEException e = assertThrows(SDJWTRequiresJOSEException.class,
                () -> JWTCredential.parseJWTCredential(token + "~"));
        assertEquals(Code.SD_JWT_REQUIRES_JOSE, e.getCode());
        assertThrows(SDJWTRequiresJOSEException.class, () -> CredentialParser.parseCredential(
                (token + "~").getBytes(StandardCharsets.UTF_8)));

        // digests inside the signed payload
        String[] p = token.split("\\.");
        Map<String, Object> payload = MAPPER.readValue(Base64.getUrlDecoder().decode(p[1]), Map.class);
        ((Map<String, Object>) ((Map<String, Object>) payload.get("vc")).get("credentialSubject"))
                .put("_sd", List.of("abc"));
        String tampered = p[0] + "." + b64(MAPPER.writeValueAsBytes(payload)) + "." + p[2];
        assertThrows(SDJWTRequiresJOSEException.class, () -> JWTCredential.parseJWTCredential(tampered));

        assertTrue(good.decodedDisclosures().isEmpty());
        assertThrows(SDJWTRequiresJOSEException.class, () -> good.present(List.of()));
    }

    // ---- 4.5 / 4.19: JWT exp/nbf under withCheckExpiration ----------------------------------------------------

    @Test
    void jwtVc_checkExpirationCoversValidityWindowAndTokenClaims() throws Exception {
        StaticDocumentResolver r = resolver(secpDoc(ISSUER));
        CredentialContents expired = contentsV1(ISSUER);
        expired.setValidUntil(Instant.now().minusSeconds(30));
        JWTCredential c = JWTCredential.newJWTCredential(expired, p256(r));
        c.addProofByProvider(new DefaultSignerProvider(SECP_PRIV), p256(r));
        c.verify(p256(r)); // plain verify does not check the window
        CredentialException e = assertThrows(CredentialException.class,
                () -> c.verify(p256(r).withCheckExpiration()));
        assertEquals(Code.EXPIRED, e.getCode());
        c.verify(p256(r).withCheckExpiration().withLeewayMs(120_000)); // leeway widens the window

        CredentialContents future = contentsV1(ISSUER);
        future.setValidFrom(Instant.now().plusSeconds(3600));
        JWTCredential f = JWTCredential.newJWTCredential(future, p256(r));
        f.addProofByProvider(new DefaultSignerProvider(SECP_PRIV), p256(r));
        String token = (String) f.serialize();
        assertEquals(Code.NOT_VALID_YET, assertThrows(CredentialException.class,
                () -> JWTCredential.parseJWTCredential(token, p256(r).withCheckExpiration())).getCode());
    }

    // ---- JSON-LD: P-256 default hex key, hash, RFC3339, proof set --------------------------------------------

    @Test
    void jsonVc_addProofHexUsesP256_hashExtractField_rfc3339() throws Exception {
        StaticDocumentResolver r = resolver(p256Doc(ISSUER));
        CredentialContents c = contents(ISSUER);
        c.setValidFrom(Instant.parse("2024-01-02T03:04:05.678Z"));
        JSONCredential vc = JSONCredential.newJSONCredential(c, p256(r));
        assertEquals("2024-01-02T03:04:05Z", vc.extractField("validFrom"));

        vc.addProof(P256_PRIV, p256(r));
        vc.verify(p256(r));
        Map<String, Object> proof = (Map<String, Object>) vc.extractField("proof");
        assertEquals("ecdsa-rdfc-2019", proof.get("cryptosuite"));
        assertTrue(((String) proof.get("created")).matches("\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\dZ"), proof.get("created").toString());
        String h1 = vc.hash();
        assertEquals(64, h1.length());
        assertEquals(h1, vc.hash());
        assertThrows(Exception.class, () -> JSONCredential.newJSONCredential(contents(ISSUER)).hash());
    }

    @Test
    void jsonVc_appendKeepsExistingRawProofFields_andRefusesReplace() throws Exception {
        StaticDocumentResolver r = resolver(p256Doc(ISSUER));
        JSONCredential vc = JSONCredential.newJSONCredential(contents(ISSUER), p256(r));
        vc.addProof(P256_PRIV, p256(r));
        Map<String, Object> data = vc.getCredentialData();
        ((Map<String, Object>) data.get("proof")).put("nonce", "keep-me");

        vc.addProof(P256_PRIV, p256(r));
        List<Map<String, Object>> proofs = (List<Map<String, Object>>) vc.getCredentialData().get("proof");
        assertEquals(2, proofs.size());
        assertEquals("keep-me", proofs.get(0).get("nonce"), "existing raw proof is not rebuilt through a DTO");

        CredentialException e = assertThrows(CredentialException.class,
                () -> vc.addProof(P256_PRIV, p256(r).withReplaceProof()));
        assertEquals(Code.UNSUPPORTED_OPTION, e.getCode());
        assertEquals(2, ((List<?>) vc.getCredentialData().get("proof")).size());
    }

    // ---- 3.27 / 3.29-3.31: external signing -------------------------------------------------------------------

    @Test
    void jsonVc_externalSigning_digestVerifyDetachedAndRefusals() throws Exception {
        StaticDocumentResolver r = resolver(p256Doc(ISSUER));
        JSONCredential vc = JSONCredential.newJSONCredential(contents(ISSUER), p256(r));
        byte[] docHash = vc.getSigningInput();
        assertEquals(32, docHash.length);

        Proof p = new Proof();
        p.setType("DataIntegrityProof");
        p.setCryptosuite("ecdsa-rdfc-2019");
        p.setCreated("2024-01-02T03:04:05Z");
        p.setVerificationMethod(ISSUER + "#key-1");
        p.setProofPurpose("assertionMethod");
        // ensure the data-integrity context is present before hashing, like the Go flow
        vc.getCredentialData().put("@context", List.of("https://www.w3.org/ns/credentials/v2"));
        byte[] toSign = vc.createProofSigning(docHash, p);
        assertEquals(32, toSign.length, "external signer signs the 32-byte SHA-256 of hashData");

        byte[] sig = new P256SignerProvider(P256_PRIV).sign(toSign);

        Proof hex = copy(p);
        hex.setProofValue("deadbeef");
        assertThrows(Exception.class, () -> vc.addCustomProof(hex));

        Proof bad = copy(p);
        bad.setProofValue(Multibase.encodeBase58Btc(new byte[64]));
        assertThrows(Exception.class, () -> vc.addCustomProof(bad, p256(r).withVerifyProof()));
        assertNull(vc.getCredentialData().get("proof"), "a failed check leaves the credential untouched");

        assertThrows(Exception.class, () -> vc.addCustomProof(copy(p), p256(r).withVerificationMethodKey("key-2")));
        assertThrows(CredentialException.class, () -> vc.addCustomProof(copy(p), p256(r).withReplaceProof()));

        Proof good = copy(p);
        good.setProofValue(Multibase.encodeBase58Btc(sig));
        vc.addCustomProof(good, p256(r).withVerifyProof());
        vc.verify(p256(r));
    }

    // ---- 3.7: low-S normalisation (secp256k1 suite) -----------------------------------------------------------

    @Test
    void secp256k1Suite_foldsHighSSignaturesToLowS() throws Exception {
        StaticDocumentResolver r = resolver(secpDoc(ISSUER));
        DefaultSignerProvider inner = new DefaultSignerProvider(SECP_PRIV);
        BigInteger n = new BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);
        SignerProvider highS = digest -> {
            byte[] sig = inner.sign(digest);
            BigInteger s = new BigInteger(1, Arrays.copyOfRange(sig, 32, 64));
            byte[] flipped = n.subtract(s).toByteArray();
            byte[] out = sig.clone();
            Arrays.fill(out, 32, 64, (byte) 0);
            System.arraycopy(flipped, Math.max(0, flipped.length - 32), out, 64 - Math.min(32, flipped.length),
                    Math.min(32, flipped.length));
            return out;
        };
        JSONCredential vc = JSONCredential.newJSONCredential(contents(ISSUER), p256(r));
        vc.addProofByProvider(highS, p256(r));
        vc.verify(p256(r)); // the verifier rejects high-S, so this only passes when signing folded it
    }

    // ---- 1.8 / 1.12 / 1.10: parse ----------------------------------------------------------------------------

    @Test
    void parse_enforcesRequiredProperties_andStatusTypeAndTermsOfUse() throws Exception {
        String missingIssuer = "{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],\"type\":[\"VerifiableCredential\"],"
                + "\"credentialSubject\":{\"id\":\"did:example:s\"}}";
        Exception e = assertThrows(Exception.class,
                () -> JSONCredential.parseJSONCredential(missingIssuer.getBytes(StandardCharsets.UTF_8)));
        assertTrue(e.getMessage().contains("missing issuer"), e.getMessage());

        CredentialContents c = contents(ISSUER);
        Status noType = new Status();
        noType.setId("https://status.example/1");
        c.setCredentialStatus(List.of(noType));
        assertThrows(IllegalArgumentException.class, () -> JSONCredential.newJSONCredential(c));

        CredentialContents t = contents(ISSUER);
        t.setTermsOfUse(List.of(new TermsOfUse("https://policy.example/1", "TrustFrameworkPolicy")));
        JSONCredential vc = JSONCredential.newJSONCredential(t);
        assertEquals("TrustFrameworkPolicy", vc.extractField("termsOfUse") instanceof List<?> l
                ? ((Map<?, ?>) l.get(0)).get("type") : null);
        t.setTermsOfUse(List.of(new TermsOfUse("https://policy.example/1", "")));
        assertThrows(IllegalArgumentException.class, () -> JSONCredential.newJSONCredential(t));
    }

    @Test
    void parseCredential_unwrapsEnvelopedVc_andRefusesBorrowedId() throws Exception {
        StaticDocumentResolver r = resolver(secpDoc(ISSUER));
        JOSECredential jose = JOSECredential.create(contents(ISSUER), p256(r));
        jose.addProofByProvider(new DefaultSignerProvider(SECP_PRIV), p256(r));
        String token = (String) jose.serialize();
        String envelope = "{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],"
                + "\"type\":[\"EnvelopedVerifiableCredential\"],\"id\":\"data:application/vc+jwt," + token + "\"}";
        Credential parsed = CredentialParser.parseCredential(envelope.getBytes(StandardCharsets.UTF_8),
                p256(r).withVerifyProof());
        assertEquals("JOSE", parsed.getType());

        String borrowed = envelope.replace("EnvelopedVerifiableCredential", "VerifiableCredential");
        assertThrows(Exception.class, () -> CredentialParser.parseCredential(borrowed.getBytes(StandardCharsets.UTF_8)));

        // ParseCredentialWithValidation = schema validation + proof verification; the credential has no
        // credentialSchema, so schema validation (required here) refuses it before the proof is looked at.
        assertEquals(Code.SCHEMA_VALIDATION, assertThrows(CredentialException.class,
                () -> CredentialParser.parseCredentialWithValidation(token.getBytes(StandardCharsets.UTF_8),
                        p256(r))).getCode());
    }

    // ---- JOSE ---------------------------------------------------------------------------------------------------

    @Test
    void jose_iat_serializeShape_expNbfAlwaysChecked_validFromChecked() throws Exception {
        StaticDocumentResolver r = resolver(secpDoc(ISSUER));
        CredentialOptions sd = p256(r).withSDSelectivePaths(List.of("credentialSubject.name"));
        JOSECredential c = JOSECredential.create(contents(ISSUER), sd);
        assertNotNull(c.extractField("iat"), "iat is set at build");
        String unsigned = (String) c.serialize();
        assertTrue(unsigned.matches("[^.~]+\\.[^.~]+~[^~]+~"), "unsigned disclosable token is h.p~d~: " + unsigned);
        assertEquals(1, c.decodedDisclosures().size());
        assertEquals("name", c.decodedDisclosures().get(0).fieldName);

        c.addProofByProvider(new DefaultSignerProvider(SECP_PRIV), p256(r));
        c.verify(p256(r));
        assertThrows(CredentialException.class,
                () -> c.addProofByProvider(new DefaultSignerProvider(SECP_PRIV), p256(r)));

        // validFrom in the future: only checked under withCheckExpiration
        CredentialContents future = contents(ISSUER);
        future.setValidFrom(Instant.now().plusSeconds(3600));
        JOSECredential f = JOSECredential.create(future, p256(r));
        f.addProofByProvider(new DefaultSignerProvider(SECP_PRIV), p256(r));
        f.verify(p256(r));
        assertEquals(Code.NOT_VALID_YET,
                assertThrows(CredentialException.class, () -> f.verify(p256(r).withCheckExpiration())).getCode());
    }

    @Test
    void jose_parse_refusesDisclosableRootAndSecuredClaimsBehindDisclosures() throws Exception {
        StaticDocumentResolver r = resolver(secpDoc(ISSUER));
        // _sd at the root of a vc+jwt
        String header = b64("{\"typ\":\"vc+jwt\",\"alg\":\"ES256K\",\"kid\":\"" + ISSUER + "#key-1\"}");
        String payload = b64("{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],\"type\":[\"VerifiableCredential\"],"
                + "\"issuer\":\"" + ISSUER + "\",\"credentialSubject\":{\"id\":\"did:example:s\"},\"_sd\":[\"x\"]}");
        Exception e = assertThrows(Exception.class, () -> JOSECredential.parse(header + "." + payload + ".sig"));
        assertTrue(e.getMessage().contains("_sd"), e.getMessage());

        // a vc+jwt must not carry machinery anywhere, not even in the subject
        String payload2 = b64("{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],\"type\":[\"VerifiableCredential\"],"
                + "\"issuer\":\"" + ISSUER + "\",\"credentialSubject\":{\"_sd\":[\"x\"]}}");
        assertThrows(Exception.class, () -> JOSECredential.parse(header + "." + payload2 + ".sig"));
    }

    @Test
    void sdjwtParse_refusesKeyBindingJwt_andDecodesDisclosures() throws Exception {
        String jwt = "aaa.bbb.ccc";
        String disclosure = b64("[\"salt\",\"name\",\"Alice\"]");
        var parsed = com.pila.credential.common.sdjwt.SDJWT.parse(jwt + "~" + disclosure + "~");
        assertEquals("name", parsed.decodedDisclosures.get(0).fieldName);
        assertEquals("Alice", parsed.decodedDisclosures.get(0).value);
        assertThrows(Exception.class, () -> com.pila.credential.common.sdjwt.SDJWT.parse(
                jwt + "~" + disclosure + "~kb.kb.kb"));
    }

    // ---- 4.24: bitstring status list --------------------------------------------------------------------------

    @Test
    void revocation_checkedFromBitstringStatusList() throws Exception {
        StaticDocumentResolver r = resolver(p256Doc(ISSUER));
        CredentialContents c = contents(ISSUER);
        Status st = new Status();
        st.setType("BitstringStatusListEntry");
        st.setStatusPurpose("revocation");
        st.setStatusListIndex("10");
        st.setStatusListCredential("https://status.example/list/1");
        c.setCredentialStatus(List.of(st));

        byte[] bits = new byte[16];
        bits[1] |= 1 << 2; // position 10
        CredentialStatus.Fetcher fetch = url -> statusList("revocation", bits);
        JSONCredential vc = JSONCredential.newJSONCredential(c, p256(r));
        vc.addProof(P256_PRIV, p256(r));

        CredentialException e = assertThrows(CredentialException.class,
                () -> vc.verify(p256(r).withCheckRevocation().withStatusFetcher(fetch)));
        assertEquals(Code.REVOKED, e.getCode());

        byte[] clean = new byte[16];
        vc.verify(p256(r).withCheckRevocation().withStatusFetcher(url -> statusList("revocation", clean)));
        // a suspension list never revokes
        vc.verify(p256(r).withCheckRevocation().withStatusFetcher(url -> statusList("suspension", bits)));
        // out-of-range index is an error, and without the option nothing is fetched
        vc.verify(p256(r).withStatusFetcher(url -> { throw new AssertionError("must not fetch"); }));
        assertThrows(Exception.class, () -> vc.verify(p256(r).withCheckRevocation()
                .withStatusFetcher(url -> statusList("revocation", new byte[1]))));
    }

    // ---- 4.25: schema validation ------------------------------------------------------------------------------

    @Test
    void schemaValidation_draft07CoreWithCustomLoader() throws Exception {
        StaticDocumentResolver r = resolver(p256Doc(ISSUER));
        CredentialContents c = contents(ISSUER);
        Schema s = new Schema();
        s.setId("https://schema.example/person");
        s.setType("JsonSchema");
        c.setSchemas(List.of(s));
        String schema = "{\"type\":\"object\",\"required\":[\"credentialSubject\"],\"properties\":{\"credentialSubject\":"
                + "{\"type\":\"object\",\"required\":[\"name\",\"age\"],\"properties\":{\"name\":{\"type\":\"string\","
                + "\"minLength\":3},\"age\":{\"type\":\"integer\",\"minimum\":18}}}}}";
        CredentialOptions opts = p256(r).withSchemaValidation()
                .withSchemaLoader(id -> schema.getBytes(StandardCharsets.UTF_8));

        // "age" is missing from the subject
        CredentialException e = assertThrows(CredentialException.class, () -> JSONCredential.newJSONCredential(c, opts));
        assertEquals(Code.SCHEMA_VALIDATION, e.getCode());
        assertTrue(e.getMessage().contains("age is required"), e.getMessage());

        c.setSubject(List.of(new Subject("did:example:s", new java.util.HashMap<>(Map.of("name", "Alice", "age", 20)))));
        JSONCredential.newJSONCredential(c, opts);
        c.setSubject(List.of(new Subject("did:example:s", new java.util.HashMap<>(Map.of("name", "Alice", "age", 12)))));
        assertThrows(CredentialException.class, () -> JSONCredential.newJSONCredential(c, opts));

        // no credentialSchema at all: required on this path
        assertThrows(CredentialException.class, () -> JSONCredential.newJSONCredential(contents(ISSUER), opts));
    }

    private static byte[] statusList(String purpose, byte[] bits) throws Exception {
        ByteArrayOutputStream gz = new ByteArrayOutputStream();
        try (GZIPOutputStream out = new GZIPOutputStream(gz)) {
            out.write(bits);
        }
        String enc = Base64.getUrlEncoder().withoutPadding().encodeToString(gz.toByteArray());
        return ("{\"data\":{\"credentialSubject\":{\"statusPurpose\":\"" + purpose + "\",\"encodedList\":\"" + enc
                + "\"}}}").getBytes(StandardCharsets.UTF_8);
    }

    private static Proof copy(Proof p) {
        Proof c = new Proof();
        c.setType(p.getType());
        c.setCryptosuite(p.getCryptosuite());
        c.setCreated(p.getCreated());
        c.setVerificationMethod(p.getVerificationMethod());
        c.setProofPurpose(p.getProofPurpose());
        c.setProofValue(p.getProofValue());
        return c;
    }

    private static String b64(String json) {
        return b64(json.getBytes(StandardCharsets.UTF_8));
    }

    private static String b64(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }
}
