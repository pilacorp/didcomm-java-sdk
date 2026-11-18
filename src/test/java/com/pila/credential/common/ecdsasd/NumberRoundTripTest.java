package com.pila.credential.common.ecdsasd;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.signer.P256SignerProvider;
import com.pila.credential.common.verificationmethod.Multikey;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** M2: the ecdsa-sd base proof signs the same number text the derived verify checks (Go json-gold's). */
class NumberRoundTripTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static Map<String, Object> fixture(String name) throws Exception {
        try (var in = NumberRoundTripTest.class.getResourceAsStream("/ecdsasd-w3c/" + name)) {
            return MAPPER.readValue(in.readAllBytes(), new TypeReference<>() {
            });
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void doublesSurviveBaseSignDeriveVerify() throws Exception {
        Map<String, Object> exp = fixture("expected.json");
        Map<String, String> basePair = (Map<String, String>) fixture("keys.json").get("baseKeyPair");
        BigInteger d = ((org.bouncycastle.jce.interfaces.ECPrivateKey) Keys
                .decodeP256PrivMultibase(basePair.get("secretKeyMultibase"))).getD();
        P256SignerProvider signer = new P256SignerProvider(String.format("%064x", d));
        PublicKey pub = Multikey.publicKeyFromMultibase(basePair.get("publicKeyMultibase"));

        for (double score : new double[] {1.5, 3103.6362735313405, 1e20}) {
            Map<String, Object> cred = fixture("credential.json");
            ((Map<String, Object>) cred.get("credentialSubject")).put("score", score);
            ((List<Object>) cred.get("@context")).add(Map.of("score", "https://example.org/score"));
            Map<String, Object> proofCfg = (Map<String, Object>) exp.get("proofConfig");
            Map<String, Object> cfg = new LinkedHashMap<>();
            cfg.put("@context", cred.get("@context"));
            for (String k : List.of("type", "cryptosuite", "created", "verificationMethod", "proofPurpose")) {
                cfg.put(k, proofCfg.get(k));
            }
            String base = EcdsaSd.createBaseProof(cred, cfg, List.of("/issuer"), signer);
            EcdsaSd.DeriveResult derived = EcdsaSd.deriveProofPair(cred, base, List.of("/credentialSubject/score"));
            Map<String, Object> reveal = derived.revealDoc();
            assertTrue(((Map<String, Object>) reveal.get("credentialSubject")).containsKey("score"));
            Map<String, Object> vcfg = new LinkedHashMap<>(cfg);
            vcfg.put("@context", reveal.get("@context"));
            assertDoesNotThrow(() -> EcdsaSd.verifyProof(reveal, vcfg, derived.proofValue(), pub), "score " + score);
        }
    }
}
