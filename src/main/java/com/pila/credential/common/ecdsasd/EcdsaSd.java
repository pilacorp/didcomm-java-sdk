package com.pila.credential.common.ecdsasd;

import com.pila.credential.common.signer.SignerProvider;

import java.security.PublicKey;
import java.util.List;
import java.util.Map;

public final class EcdsaSd {

    public static final String CRYPTOSUITE = "ecdsa-sd-2023";

    private EcdsaSd() {
    }

    public static String createBaseProof(Map<String, Object> document, Map<String, Object> proofConfig,
            List<String> mandatoryPointers, SignerProvider issuerSigner) throws Exception {
        return createBaseProof(document, proofConfig, mandatoryPointers, issuerSigner, null);
    }

    public static String createBaseProof(Map<String, Object> document, Map<String, Object> proofConfig,
            List<String> mandatoryPointers, SignerProvider issuerSigner, PublicKey issuerPub) throws Exception {
        return Sign.createBaseProof(document, proofConfig, mandatoryPointers, issuerSigner, issuerPub);
    }

    public record DeriveResult(Map<String, Object> revealDoc, String proofValue) {
    }

    public static DeriveResult deriveProofPair(Map<String, Object> document, String baseProofValue,
            List<String> selectivePointers) throws Exception {
        Disclose.DisclosureData dd = Disclose.createDisclosureData(document, baseProofValue, selectivePointers);
        ProofValue.SpecDerivedProof dp = new ProofValue.SpecDerivedProof();
        dp.baseSignature = dd.baseSignature;
        dp.publicKey = dd.publicKey;
        dp.signatures = dd.signatures;
        dp.labelMap = dd.labelMap;
        dp.mandatoryIndexes = dd.mandatoryIndexes;
        return new DeriveResult(dd.revealDoc, ProofValue.serializeDisclosureProofValue(dp));
    }

    public static void verifyProof(Map<String, Object> document, Map<String, Object> proofConfig, String proofValue,
            PublicKey issuerPub) throws Exception {
        Verify.verifyProof(document, proofConfig, proofValue, issuerPub);
    }
}
