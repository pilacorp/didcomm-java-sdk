package com.pila.credential.common.ecdsasd;

import com.pila.credential.common.crypto.Crypto;
import com.pila.credential.common.processor.Processor;
import com.pila.credential.common.signer.SignerProvider;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

final class Sign {

    private Sign() {
    }

    static String createBaseProof(Map<String, Object> document, Map<String, Object> proofConfig,
            List<String> mandatoryPointers, SignerProvider issuerSigner, PublicKey issuerPub) throws Exception {
        byte[] proofHash = Hashes.hashProofConfig(proofConfig);
        byte[] hmacKey = new byte[32];
        new SecureRandom().nextBytes(hmacKey);

        Map<String, List<String>> groups = Map.of("mandatory", mandatoryPointers);
        LabelMap.GroupedCanon grouped = LabelMap.canonicalizeAndGroup(document, hmacKey, groups);
        LabelMap.GroupIndexes mg = grouped.groups.get("mandatory");
        List<String> nonMandatory = Helpers.orderedValues(mg.nonMatching);
        byte[] mandatoryHash = Hashes.hashMandatory(mg.matching);

        Keys.EphemeralKey eph = Keys.newEphemeralKey();
        List<byte[]> signatures = new ArrayList<>(nonMandatory.size());
        for (String nq : nonMandatory) {
            signatures.add(eph.signStatement(nq));
        }
        byte[] ephPub = Keys.pubToMultikeyBytes(eph.publicKey());

        byte[] toSign = new byte[proofHash.length + ephPub.length + mandatoryHash.length];
        System.arraycopy(proofHash, 0, toSign, 0, proofHash.length);
        System.arraycopy(ephPub, 0, toSign, proofHash.length, ephPub.length);
        System.arraycopy(mandatoryHash, 0, toSign, proofHash.length + ephPub.length, mandatoryHash.length);
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(toSign);
        byte[] baseSig = issuerSigner.sign(digest);
        if (issuerPub != null && !Crypto.verifyEcdsaRaw(issuerPub, digest, baseSig)) {
            throw new Exception(
                    "ecdsasd: the base signature does not verify against the verification method; the signer does not hold that key");
        }

        ProofValue.SpecBaseProof bp = new ProofValue.SpecBaseProof();
        bp.baseSignature = baseSig;
        bp.publicKey = ephPub;
        bp.hmacKey = hmacKey;
        bp.signatures = signatures;
        bp.mandatoryPointers = mandatoryPointers;
        return ProofValue.serializeBaseProofValue(bp);
    }
}
