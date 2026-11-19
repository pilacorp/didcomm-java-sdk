package com.pila.credential.common.ecdsasd;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.signer.P256SignerProvider;
import com.pila.credential.common.verificationmethod.Multikey;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.HexFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

class W3cEcdsaSdConformanceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static byte[] readFixture(String name) throws Exception {
        try (InputStream in = W3cEcdsaSdConformanceTest.class.getResourceAsStream("/ecdsasd-w3c/" + name)) {
            if (in == null) {
                throw new IllegalStateException("missing classpath fixture ecdsa-w3c/" + name);
            }
            return in.readAllBytes();
        }
    }

    private static Map<String, Object> loadCred() throws Exception {
        return MAPPER.readValue(readFixture("credential.json"), new TypeReference<>() {
        });
    }

    private static Map<String, Object> loadExpected() throws Exception {
        return MAPPER.readValue(readFixture("expected.json"), new TypeReference<>() {
        });
    }

    private static Map<String, Object> loadKeys() throws Exception {
        return MAPPER.readValue(readFixture("keys.json"), new TypeReference<>() {
        });
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> w3cProofConfig(Map<String, Object> exp, Map<String, Object> cred)
            throws Exception {
        Map<String, Object> proofConfig = (Map<String, Object>) exp.get("proofConfig");
        Map<String, Object> cfg = new java.util.LinkedHashMap<>();
        cfg.put("@context", cred.get("@context"));
        cfg.put("type", proofConfig.get("type"));
        cfg.put("cryptosuite", proofConfig.get("cryptosuite"));
        cfg.put("created", proofConfig.get("created"));
        cfg.put("verificationMethod", proofConfig.get("verificationMethod"));
        cfg.put("proofPurpose", proofConfig.get("proofPurpose"));
        return cfg;
    }

    @Test
    void phase4_hashes() throws Exception {
        Map<String, Object> cred = loadCred();
        Map<String, Object> exp = loadExpected();
        byte[] hmacKey = HexFormat.of().parseHex((String) ((Map<?, ?>) loadKeys()).get("hmacKeyString"));

        byte[] ph = Hashes.hashProofConfig(w3cProofConfig(exp, cred));
        assertEquals(exp.get("proofHash"), HexFormat.of().formatHex(ph));

        LabelMap.GroupedCanon grouped = LabelMap.canonicalizeAndGroup(cred, hmacKey,
                Map.of("mandatory", List.of("/issuer")));
        byte[] mh = Hashes.hashMandatory(grouped.groups.get("mandatory").matching);
        assertEquals(exp.get("mandatoryHash"), HexFormat.of().formatHex(mh));
    }

    @Test
    void phase5_roundTrip() throws Exception {
        Map<String, Object> cred = loadCred();
        Map<String, Object> exp = loadExpected();
        Map<String, Object> keys = loadKeys();
        @SuppressWarnings("unchecked")
        Map<String, String> basePair = (Map<String, String>) keys.get("baseKeyPair");
        var issuerPriv = Keys.decodeP256PrivMultibase(basePair.get("secretKeyMultibase"));
        BigInteger d = ((org.bouncycastle.jce.interfaces.ECPrivateKey) issuerPriv).getD();
        P256SignerProvider issuerSigner = new P256SignerProvider(String.format("%064x", d));

        String basePv = EcdsaSd.createBaseProof(cred, w3cProofConfig(exp, cred), List.of("/issuer"), issuerSigner);
        @SuppressWarnings("unchecked")
        List<String> selective = (List<String>) ((Map<?, ?>) exp.get("derived")).get("selectivePointers");
        EcdsaSd.DeriveResult derived = EcdsaSd.deriveProofPair(cred, basePv, selective);

        PublicKey issuerPub = Multikey.publicKeyFromMultibase(basePair.get("publicKeyMultibase"));
        Map<String, Object> reveal = derived.revealDoc();
        assertDoesNotThrow(() -> EcdsaSd.verifyProof(reveal, w3cProofConfig(exp, reveal), derived.proofValue(),
                issuerPub));
    }

    @Test
    void phase2_selectJsonLd() throws Exception {
        Map<String, Object> cred = loadCred();
        @SuppressWarnings("unchecked")
        Map<String, List<String>> ptr = MAPPER.readValue(readFixture("pointers.json"), new TypeReference<>() {
        });
        List<String> combined = new ArrayList<>(ptr.get("mandatoryPointers"));
        combined.addAll(ptr.get("selectivePointers"));
        Map<String, Object> got = Pointer.selectJsonLd(cred, combined);
        Map<String, Object> want = MAPPER.readValue(readFixture("reveal.json"), new TypeReference<>() {
        });
        assertEquals(want, got);
    }

    @Test
    void phase8_verifyDerived() throws Exception {
        Map<String, Object> cred = loadCred();
        Map<String, Object> exp = loadExpected();
        Map<String, Object> keys = loadKeys();
        @SuppressWarnings("unchecked")
        Map<String, String> basePair = (Map<String, String>) keys.get("baseKeyPair");
        @SuppressWarnings("unchecked")
        List<String> selective = (List<String>) ((Map<?, ?>) exp.get("derived")).get("selectivePointers");

        Disclose.DisclosureData dd = Disclose.createDisclosureData(cred, (String) exp.get("baseProofValue"), selective);
        @SuppressWarnings("unchecked")
        List<Integer> wantIdx = (List<Integer>) ((Map<?, ?>) exp.get("derived")).get("adjMandatoryIndexes");
        assertEquals(wantIdx, dd.mandatoryIndexes);
        @SuppressWarnings("unchecked")
        Map<String, String> wantLabelMap = (Map<String, String>) ((Map<?, ?>) exp.get("derived")).get("labelMap");
        assertEquals(wantLabelMap, dd.labelMap);
        ProofValue.SpecDerivedProof dp = new ProofValue.SpecDerivedProof();
        dp.baseSignature = dd.baseSignature;
        dp.publicKey = dd.publicKey;
        dp.signatures = dd.signatures;
        dp.labelMap = dd.labelMap;
        dp.mandatoryIndexes = dd.mandatoryIndexes;
        String derivedPv = ProofValue.serializeDisclosureProofValue(dp);
        PublicKey issuerPub = Multikey.publicKeyFromMultibase(basePair.get("publicKeyMultibase"));
        Map<String, Object> reveal = dd.revealDoc;
        assertDoesNotThrow(() -> Verify.verifyDerivedProof(reveal, w3cProofConfig(exp, reveal), derivedPv, issuerPub));
    }
}
