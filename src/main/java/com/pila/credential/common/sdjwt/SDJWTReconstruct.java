package com.pila.credential.common.sdjwt;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Reconstruct an SD-JWT payload from digests and disclosures.
 */
public final class SDJWTReconstruct {

    private SDJWTReconstruct() {
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> reconstruct(
            Map<String, Object> vcMap, List<String> disclosures, boolean validateAlg) throws Exception {
        String sdAlg = validateAndGetAlgorithm(vcMap, validateAlg);
        Map<String, DisclosureInfo> disclosureMap = buildDisclosureMap(disclosures, sdAlg);
        Set<String> used = new HashSet<>();

        Map<String, Object> rootCopy = SDJWT.deepCopyMap(vcMap);
        Object processed = processNode(rootCopy, disclosureMap, used);
        for (String digest : disclosureMap.keySet()) {
            if (!used.contains(digest)) {
                throw new Exception("disclosure for digest \"" + digest + "\" matches nothing in the payload");
            }
        }
        if (!(processed instanceof Map<?, ?>)) {
            throw new Exception("processed payload is not an object");
        }
        Map<String, Object> result = (Map<String, Object>) processed;
        result.remove("_sd_alg");
        return result;
    }

    private static String validateAndGetAlgorithm(Map<String, Object> vcMap, boolean validateAlg)
            throws Exception {
        String sdAlg = SDJWT.DEFAULT_HASH_ALGORITHM;
        Object raw = vcMap.get("_sd_alg");
        if (raw instanceof String s && !s.isEmpty()) {
            sdAlg = s;
        }
        if (validateAlg && !SDJWT.isSupportedHashAlgorithm(sdAlg)) {
            throw new Exception("unsupported _sd_alg: \"" + sdAlg + "\"");
        }
        return sdAlg;
    }

    private static Map<String, DisclosureInfo> buildDisclosureMap(List<String> disclosures, String sdAlg)
            throws Exception {
        Map<String, DisclosureInfo> out = new java.util.LinkedHashMap<>();
        if (disclosures == null) {
            return out;
        }
        for (String disc : disclosures) {
            if (disc == null || disc.isEmpty()) {
                continue;
            }
            String h = SDJWT.hashDisclosure(sdAlg, disc);
            DisclosureInfo info = SDJWT.parseDisclosure(disc);
            if (out.containsKey(h)) {
                throw new Exception("disclosure for digest \"" + h + "\" was sent more than once");
            }
            out.put(h, info);
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static Object processNode(
            Object node, Map<String, DisclosureInfo> disclosureMap, Set<String> used) throws Exception {
        if (node instanceof List<?> list) {
            List<Object> out = new java.util.ArrayList<>();
            Set<String> arrayDigests = new HashSet<>();
            for (Object elem : list) {
                if (elem instanceof Map<?, ?> map && map.size() == 1 && map.containsKey("...")) {
                    Object hObj = map.get("...");
                    if (hObj instanceof String h) {
                        if (arrayDigests.contains(h)) {
                            throw new Exception("duplicate digest \"" + h + "\" found in array");
                        }
                        arrayDigests.add(h);
                        if (used.contains(h)) {
                            throw new Exception("digest \"" + h + "\" is referenced more than once in the payload");
                        }
                        used.add(h);

                        DisclosureInfo info = disclosureMap.get(h);
                        if (info == null) {
                            out.add(SDJWT.newDisclosurePlaceholder(h));
                            continue;
                        }
                        if (!info.isArrayElem) {
                            throw new Exception("object field disclosure used in array context");
                        }
                        out.add(processNode(info.value, disclosureMap, used));
                        continue;
                    }
                }
                out.add(processNode(elem, disclosureMap, used));
            }
            return out;
        }

        if (node instanceof Map<?, ?> rawObj) {
            Map<String, Object> obj = (Map<String, Object>) rawObj;
            Object rawSd = obj.get("_sd");
            for (Map.Entry<String, Object> entry : new java.util.ArrayList<>(obj.entrySet())) {
                if (!"_sd".equals(entry.getKey())) {
                    obj.put(entry.getKey(), processNode(entry.getValue(), disclosureMap, used));
                }
            }
            if (rawSd != null) {
                if (!(rawSd instanceof List<?> sdList) || !sdList.stream().allMatch(x -> x instanceof String)) {
                    throw new Exception("_sd must be an array of digests");
                }
                List<String> hashes = sdList.stream().map(x -> (String) x).toList();
                applySDHashes(hashes, obj, disclosureMap, new HashSet<>(), used);
                obj.remove("_sd");
            }
            return obj;
        }

        return node;
    }

    @SuppressWarnings("unchecked")
    private static void applySDHashes(
            List<String> hashes,
            Map<String, Object> v,
            Map<String, DisclosureInfo> disclosureMap,
            Set<String> objectDigests,
            Set<String> used) throws Exception {
        for (String h : hashes) {
            if (objectDigests.contains(h)) {
                throw new Exception("duplicate digest \"" + h + "\" found in _sd array");
            }
            objectDigests.add(h);
            if (used.contains(h)) {
                throw new Exception("digest \"" + h + "\" is referenced more than once in the payload");
            }
            used.add(h);

            DisclosureInfo info = disclosureMap.get(h);
            if (info == null) {
                continue;
            }
            if (info.isArrayElem || info.objectField.isEmpty()) {
                throw new Exception("array element disclosure used in object context");
            }
            if (v.containsKey(info.objectField)) {
                throw new Exception(
                        "duplicate field \"" + info.objectField + "\" when reconstructing SD-JWT object");
            }
            v.put(info.objectField, processNode(info.value, disclosureMap, used));
        }
    }
}
