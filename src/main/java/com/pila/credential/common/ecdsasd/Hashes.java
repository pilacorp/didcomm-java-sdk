package com.pila.credential.common.ecdsasd;

import com.pila.credential.common.processor.Processor;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;

public final class Hashes {

    private Hashes() {
    }

    public static byte[] hashProofConfig(Map<String, Object> proofConfig) throws Exception {
        byte[] nquads = Processor.canonicalizeForSd(proofConfig);
        return MessageDigest.getInstance("SHA-256").digest(nquads);
    }

    public static byte[] hashMandatory(Map<Integer, String> matching) throws Exception {
        StringBuilder sb = new StringBuilder();
        for (Integer i : Helpers.sortedIndexes(matching)) {
            sb.append(matching.get(i));
        }
        return MessageDigest.getInstance("SHA-256").digest(sb.toString().getBytes(StandardCharsets.UTF_8));
    }
}
