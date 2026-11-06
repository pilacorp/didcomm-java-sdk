package com.pila.credential.common.ecdsasd;

import com.pila.credential.common.crypto.Crypto;
import com.pila.credential.common.processor.Processor;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class Verify {

    private Verify() {
    }

    static void verifyBaseProof(Map<String, Object> document, Map<String, Object> proofConfig, String baseProofValue,
            PublicKey issuerPub) throws Exception {
        ProofValue.SpecBaseProof bp = ProofValue.parseBaseProofValue(baseProofValue);
        PublicKey ephPub = Keys.ecPubFromMultikeyBytes(bp.publicKey);

        LabelMap.GroupedCanon grouped = LabelMap.canonicalizeAndGroup(document, bp.hmacKey,
                Map.of("mandatory", bp.mandatoryPointers));
        LabelMap.GroupIndexes mg = grouped.groups.get("mandatory");
        List<String> nonMandatory = Helpers.orderedValues(mg.nonMatching);
        byte[] mandatoryHash = Hashes.hashMandatory(mg.matching);
        byte[] proofHash = Hashes.hashProofConfig(proofConfig);

        byte[] signData = new byte[proofHash.length + bp.publicKey.length + mandatoryHash.length];
        System.arraycopy(proofHash, 0, signData, 0, proofHash.length);
        System.arraycopy(bp.publicKey, 0, signData, proofHash.length, bp.publicKey.length);
        System.arraycopy(mandatoryHash, 0, signData, proofHash.length + bp.publicKey.length, mandatoryHash.length);
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(signData);
        if (!Crypto.verifyEcdsaRaw(issuerPub, digest, bp.baseSignature)) {
            throw new Exception("ecdsasd: issuer base signature invalid");
        }
        if (bp.signatures.size() != nonMandatory.size()) {
            throw new Exception("ecdsasd: signature count " + bp.signatures.size() + " != non-mandatory quads "
                    + nonMandatory.size());
        }
        for (int i = 0; i < nonMandatory.size(); i++) {
            byte[] d = MessageDigest.getInstance("SHA-256")
                    .digest(nonMandatory.get(i).getBytes(StandardCharsets.UTF_8));
            if (!Keys.verifyP256(ephPub, d, bp.signatures.get(i))) {
                throw new Exception("ecdsasd: non-mandatory statement signature invalid: " + nonMandatory.get(i));
            }
        }
    }

    static void verifyDerivedProof(Map<String, Object> revealDoc, Map<String, Object> proofConfig,
            String derivedProofValue, PublicKey issuerPub) throws Exception {
        ProofValue.SpecDerivedProof dp = ProofValue.parseDisclosureProofValue(derivedProofValue);
        PublicKey ephPub = Keys.ecPubFromMultikeyBytes(dp.publicKey);

        var canon = Processor.canonicalizeWithIdMap(revealDoc);
        List<String> relabeled = new ArrayList<>(LabelMap.relabelBlankNodes(canon.nquads(), dp.labelMap));
        relabeled.sort(String::compareTo);

        Set<Integer> mandatorySet = new HashSet<>(dp.mandatoryIndexes);
        List<String> mandatory = new ArrayList<>();
        List<String> nonMandatory = new ArrayList<>();
        for (int i = 0; i < relabeled.size(); i++) {
            if (mandatorySet.contains(i)) {
                mandatory.add(relabeled.get(i));
            } else {
                nonMandatory.add(relabeled.get(i));
            }
        }

        byte[] proofHash = Hashes.hashProofConfig(proofConfig);
        StringBuilder mb = new StringBuilder();
        for (String nq : mandatory) {
            mb.append(nq);
        }
        byte[] mandatoryHash = MessageDigest.getInstance("SHA-256")
                .digest(mb.toString().getBytes(StandardCharsets.UTF_8));

        byte[] signData = new byte[proofHash.length + dp.publicKey.length + mandatoryHash.length];
        System.arraycopy(proofHash, 0, signData, 0, proofHash.length);
        System.arraycopy(dp.publicKey, 0, signData, proofHash.length, dp.publicKey.length);
        System.arraycopy(mandatoryHash, 0, signData, proofHash.length + dp.publicKey.length, mandatoryHash.length);
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(signData);
        if (!Crypto.verifyEcdsaRaw(issuerPub, digest, dp.baseSignature)) {
            throw new Exception("ecdsasd: issuer base signature invalid");
        }
        if (dp.signatures.size() != nonMandatory.size()) {
            throw new Exception("ecdsasd: signature count " + dp.signatures.size() + " != non-mandatory quads "
                    + nonMandatory.size());
        }
        for (int i = 0; i < nonMandatory.size(); i++) {
            byte[] d = MessageDigest.getInstance("SHA-256")
                    .digest(nonMandatory.get(i).getBytes(StandardCharsets.UTF_8));
            if (!Keys.verifyP256(ephPub, d, dp.signatures.get(i))) {
                throw new Exception("ecdsasd: non-mandatory statement signature invalid: " + nonMandatory.get(i));
            }
        }
    }

    static void verifyProof(Map<String, Object> document, Map<String, Object> proofConfig, String proofValue,
            PublicKey issuerPub) throws Exception {
        try {
            ProofValue.decodeProofValue(proofValue, ProofValue.BASE_PROOF_HEADER);
            verifyBaseProof(document, proofConfig, proofValue, issuerPub);
            return;
        } catch (Exception ignored) {
            // try derived
        }
        try {
            ProofValue.decodeProofValue(proofValue, ProofValue.DERIVED_PROOF_HEADER);
            verifyDerivedProof(document, proofConfig, proofValue, issuerPub);
            return;
        } catch (Exception e) {
            if (e.getMessage() != null && (e.getMessage().startsWith("ecdsasd: issuer")
                    || e.getMessage().contains("statement"))) {
                throw e;
            }
        }
        throw new Exception("ecdsasd: unrecognized proof value header");
    }
}
