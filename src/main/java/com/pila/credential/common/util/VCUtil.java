package com.pila.credential.common.util;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.dto.Proof;
import com.pila.credential.common.jsonmap.JSONMap;

import java.util.*;
import java.util.function.Function;

/**
 * Utility functions for Verifiable Credentials.
 */
public class VCUtil {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Serializes a list of Proof objects to a JSON-LD compatible format.
     */
    public static Object serializeProofs(List<Proof> proofs) {
        if (proofs == null || proofs.isEmpty()) {
            return null;
        }

        List<JSONMap> result = new ArrayList<>();
        for (Proof proof : proofs) {
            JSONMap proofMap = new JSONMap();
            if (proof.getType() != null && !proof.getType().isEmpty()) {
                proofMap.put("type", proof.getType());
            }
            if (proof.getCreated() != null && !proof.getCreated().isEmpty()) {
                proofMap.put("created", proof.getCreated());
            }
            if (proof.getVerificationMethod() != null && !proof.getVerificationMethod().isEmpty()) {
                proofMap.put("verificationMethod", proof.getVerificationMethod());
            }
            if (proof.getProofPurpose() != null && !proof.getProofPurpose().isEmpty()) {
                proofMap.put("proofPurpose", proof.getProofPurpose());
            }
            if (proof.getProofValue() != null && !proof.getProofValue().isEmpty()) {
                proofMap.put("proofValue", proof.getProofValue());
            }
            if (proof.getCryptosuite() != null && !proof.getCryptosuite().isEmpty()) {
                proofMap.put("cryptosuite", proof.getCryptosuite());
            }
            result.add(proofMap);
        }

        if (result.size() == 1) {
            return result.get(0);
        }
        return result;
    }

    /**
     * Serializes types to a JSON-LD compatible format.
     */
    public static Object serializeTypes(List<String> types) {
        if (types == null || types.isEmpty()) {
            return null;
        }
        if (types.size() == 1) {
            return types.get(0);
        }
        return mapSlice(types, Function.identity());
    }

    /**
     * Maps a list of type T to a list of type U using a mapping function.
     */
    public static <T, U> List<U> mapSlice(List<T> slice, Function<T, U> mapFn) {
        if (slice == null) {
            return new ArrayList<>();
        }
        List<U> result = new ArrayList<>(slice.size());
        for (T item : slice) {
            result.add(mapFn.apply(item));
        }
        return result;
    }

    /**
     * Validates and converts a list of JSON-LD context entries.
     */
    public static List<Object> serializeContexts(List<Object> contexts) throws Exception {
        if (contexts == null) {
            return new ArrayList<>();
        }

        List<Object> validated = new ArrayList<>(contexts.size());
        for (int i = 0; i < contexts.size(); i++) {
            Object ctx = contexts.get(i);
            if (ctx == null) {
                throw new Exception("failed to validate context: context entry at index " + i + " is null");
            }

            if (ctx instanceof String) {
                String ctxStr = (String) ctx;
                if (ctxStr.isEmpty()) {
                    throw new Exception("failed to validate context: context string at index " + i + " is empty");
                }
                validated.add(ctxStr);
            } else if (ctx instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> ctxMap = (Map<String, Object>) ctx;
                if (ctxMap.containsKey("@context")) {
                    throw new Exception("failed to validate context: context object at index " + i
                            + " must not contain nested @context");
                }
                for (Map.Entry<String, Object> entry : ctxMap.entrySet()) {
                    if (entry.getKey().isEmpty()) {
                        throw new Exception(
                                "failed to validate context: context object at index " + i + " has empty key");
                    }
                    if (entry.getValue() instanceof String && ((String) entry.getValue()).isEmpty()) {
                        throw new Exception("failed to validate context: context object at index " + i
                                + " has empty string value for key \"" + entry.getKey() + "\"");
                    }
                }
                validated.add(ctxMap);
            } else {
                throw new Exception("failed to validate context: invalid context entry at index " + i
                        + ": must be string or map, got " + ctx.getClass().getName());
            }
        }
        return validated;
    }

    /**
     * Splits a JSON object into two maps: one with specified fields, one with the
     * rest.
     */
    public static Map<String, Object>[] splitJSONObj(Map<String, Object> json, String... fields) {
        Set<String> fieldSet = new HashSet<>(Arrays.asList(fields));
        Map<String, Object> fieldsMap = new HashMap<>();
        Map<String, Object> rest = new HashMap<>();

        for (Map.Entry<String, Object> entry : json.entrySet()) {
            if (fieldSet.contains(entry.getKey())) {
                fieldsMap.put(entry.getKey(), entry.getValue());
            } else {
                rest.put(entry.getKey(), entry.getValue());
            }
        }

        @SuppressWarnings("unchecked")
        Map<String, Object>[] result = new Map[2];
        result[0] = fieldsMap;
        result[1] = rest;
        return result;
    }

    /**
     * Creates a shallow copy of a JSON object.
     */
    public static Map<String, Object> shallowCopyObj(Map<String, Object> json) {
        if (json == null) {
            return new HashMap<>();
        }
        return new HashMap<>(json);
    }

    /**
     * Converts an object, string, or bytes to a JSON object represented by a map.
     */
    public static Map<String, Object> toMap(Object v) throws Exception {
        byte[] b;

        if (v instanceof byte[]) {
            b = (byte[]) v;
        } else if (v instanceof String) {
            b = ((String) v).getBytes();
        } else {
            b = objectMapper.writeValueAsBytes(v);
        }

        return objectMapper.readValue(b,
                new TypeReference<Map<String, Object>>() {
                });
    }
}
