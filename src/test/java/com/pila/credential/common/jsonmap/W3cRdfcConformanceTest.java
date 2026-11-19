package com.pila.credential.common.jsonmap;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.dto.Proof;
import com.pila.credential.common.processor.Processor;
import com.pila.credential.common.util.Multibase;
import java.security.PublicKey;
import com.pila.credential.common.signer.P256SignerProvider;
import com.pila.credential.common.verificationmethod.DidKeyP256Resolver;
import com.pila.credential.common.verificationmethod.Multikey;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * W3C ecdsa-rdfc-2019 P-256 byte-exact gate (vectors from go-credential-sdk).
 */
class W3cRdfcConformanceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static byte[] readFixture(String name) throws Exception {
        try (InputStream in = W3cRdfcConformanceTest.class.getResourceAsStream("/w3c-rdfc-p256/" + name)) {
            if (in == null) {
                throw new IllegalStateException("missing classpath fixture w3c-rdfc-p256/" + name);
            }
            return in.readAllBytes();
        }
    }

    private static String readHex(String name) throws Exception {
        return new String(readFixture(name), StandardCharsets.UTF_8).trim();
    }

    private static JSONMap signedDoc() throws Exception {
        return MAPPER.readValue(readFixture("signedECDSAP256.json"), JSONMap.class);
    }

    private static Map<String, Object> unsignedDoc() throws Exception {
        Map<String, Object> doc = MAPPER.readValue(readFixture("signedECDSAP256.json"),
                new TypeReference<>() {});
        doc.remove("proof");
        return doc;
    }

    private static Map<String, Object> proofConfigFixture() throws Exception {
        return MAPPER.readValue(readFixture("proofConfigECDSAP256.json"), new TypeReference<>() {});
    }

    private static Proof proofFromSigned() throws Exception {
        Map<String, Object> wrapper = MAPPER.readValue(readFixture("signedECDSAP256.json"),
                new TypeReference<>() {});
        Object proofObj = wrapper.get("proof");
        return MAPPER.convertValue(proofObj, Proof.class);
    }

    @Test
    void fixturesPresent() throws Exception {
        for (String name : new String[] {
                "signedECDSAP256.json",
                "proofConfigECDSAP256.json",
                "canonDocECDSAP256.txt",
                "proofCanonECDSAP256.txt",
                "docHashECDSAP256.txt",
                "proofHashECDSAP256.txt",
                "combinedHashECDSAP256.txt",
                "sigHexECDSAP256.txt",
                "sigBTC58ECDSAP256.txt",
                "p256KeyPair.json"
        }) {
            assertTrue(W3cRdfcConformanceTest.class.getResource("/w3c-rdfc-p256/" + name) != null,
                    "missing " + name);
        }
    }

    @Test
    void phase1_canonicalizeDocument() throws Exception {
        byte[] got = Processor.canonicalizeDocument(unsignedDoc());
        assertEquals(new String(readFixture("canonDocECDSAP256.txt"), StandardCharsets.UTF_8),
                new String(got, StandardCharsets.UTF_8));
    }

    @Test
    void phase2_canonicalizeProofConfig() throws Exception {
        byte[] got = Processor.canonicalizeDocument(proofConfigFixture());
        assertEquals(new String(readFixture("proofCanonECDSAP256.txt"), StandardCharsets.UTF_8),
                new String(got, StandardCharsets.UTF_8));
    }

    @Test
    void phase2b_buildProofConfig() throws Exception {
        JSONMap doc = signedDoc();
        Map<String, Object> cfg = doc.ecdsaProofConfig(proofFromSigned());
        byte[] got = Processor.canonicalizeDocument(cfg);
        assertEquals(new String(readFixture("proofCanonECDSAP256.txt"), StandardCharsets.UTF_8),
                new String(got, StandardCharsets.UTF_8));
    }

    @Test
    void phase3_hashes() throws Exception {
        byte[] docCanon = Processor.canonicalizeDocument(unsignedDoc());
        String docHash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(docCanon));
        assertEquals(readHex("docHashECDSAP256.txt"), docHash);

        byte[] cfgCanon = Processor.canonicalizeDocument(proofConfigFixture());
        String proofHash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(cfgCanon));
        assertEquals(readHex("proofHashECDSAP256.txt"), proofHash);
    }

    @Test
    void phase4_hashData() throws Exception {
        JSONMap doc = signedDoc();
        byte[] got = doc.ecdsaHashData(proofFromSigned());
        assertEquals(readHex("combinedHashECDSAP256.txt"), HexFormat.of().formatHex(got));
    }

    @Test
    void phase5_proofValueEncoding() throws Exception {
        String sigHex = readHex("sigHexECDSAP256.txt");
        byte[] sig = HexFormat.of().parseHex(sigHex);
        assertEquals(64, sig.length);

        String mb = Multibase.encodeBase58Btc(sig);
        assertEquals(readHex("sigBTC58ECDSAP256.txt"), mb);

        Proof proof = proofFromSigned();
        byte[] decoded = Multibase.decodeBase58Btc(proof.getProofValue());
        assertEquals(sigHex, HexFormat.of().formatHex(decoded));
    }

    @Test
    void proofConfigContextComesFromDocument() throws Exception {
        JSONMap doc = signedDoc();
        Map<String, Object> cfg = doc.ecdsaProofConfig(proofFromSigned());
        assertEquals(doc.get("@context"), cfg.get("@context"));
        byte[] got = Processor.canonicalizeDocument(cfg);
        assertEquals(new String(readFixture("proofCanonECDSAP256.txt"), StandardCharsets.UTF_8),
                new String(got, StandardCharsets.UTF_8));
    }

    @Test
    void phase7_verifyProofWithDidKey() throws Exception {
        JSONMap doc = signedDoc();
        DidKeyP256Resolver resolver = new DidKeyP256Resolver();
        assertTrue(doc.verifyProof(resolver));

        JSONMap tampered = signedDoc();
        @SuppressWarnings("unchecked")
        Map<String, Object> proof = (Map<String, Object>) tampered.get("proof");
        String pv = (String) proof.get("proofValue");
        int i = pv.length() / 2;
        char swap = pv.charAt(i) == 'A' ? 'B' : 'A';
        proof.put("proofValue", pv.substring(0, i) + swap + pv.substring(i + 1));
        assertFalse(tampered.verifyProof(resolver));
    }

    @Test
    void javaSignatureVerifiesWithW3cIssuerKey() throws Exception {
        JSONMap doc = signedDoc();
        Proof proof = proofFromSigned();
        byte[] hashData = doc.ecdsaHashData(proof);
        byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(hashData);

        Map<String, Object> kp = MAPPER.readValue(readFixture("p256KeyPair.json"), new TypeReference<>() {});
        var priv = com.pila.credential.common.ecdsasd.Keys.decodeP256PrivMultibase(
                (String) kp.get("secretKeyMultibase"));
        java.math.BigInteger d = ((org.bouncycastle.jce.interfaces.ECPrivateKey) priv).getD();
        P256SignerProvider signer = new P256SignerProvider(String.format("%064x", d));
        byte[] sig = signer.sign(digest);
        PublicKey pub = Multikey.publicKeyFromMultibase((String) kp.get("publicKeyMultibase"));
        assertTrue(com.pila.credential.common.crypto.Crypto.verifyEcdsaRaw(pub, digest, sig));
    }

    @Test
    void w3cIssuerMultibaseMatchesGoVector() throws Exception {
        String multibase = "zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP";
        assertTrue(Multikey.isP256PublicMultibase(multibase));
        Multikey.publicKeyFromMultibase(multibase);
    }
}
