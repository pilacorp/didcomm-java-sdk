package com.pila.credential.common.sdjwt;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * Build SD-JWT disclosures at issuing time.
 */
public final class SDJWTDisclosure {

    private static final Random SHUFFLE_RANDOM = new Random();

    private SDJWTDisclosure() {
    }

    public static SDJWTResult buildDisclosures(BuildDisclosuresInput input) throws Exception {
        String sdAlg = input.hashAlgorithm != null ? input.hashAlgorithm : SDJWT.DEFAULT_HASH_ALGORITHM;
        if (!SDJWT.isSupportedHashAlgorithm(sdAlg)) {
            throw new Exception("unsupported hash algorithm \"" + sdAlg + "\"");
        }

        Map<String, Object> processedVC = SDJWT.deepCopyMap(input.vc);
        List<BuildDisclosuresInput.DecoyConfig> decoys =
                input.decoys != null ? input.decoys : List.of();
        List<String> selectivePaths =
                input.selectivePaths != null ? input.selectivePaths : List.of();

        if (!decoys.isEmpty()) {
            processedVC.put("_sd_alg", sdAlg);
        }
        if (selectivePaths.isEmpty() && decoys.isEmpty()) {
            return new SDJWTResult(processedVC, List.of());
        }
        if (!selectivePaths.isEmpty()) {
            processedVC.put("_sd_alg", sdAlg);
        }

        List<String> disclosures = processSelectivePaths(processedVC, selectivePaths, sdAlg);
        processDecoys(processedVC, decoys, sdAlg);

        if (Boolean.TRUE.equals(input.shuffle)) {
            shuffleSDArrays(processedVC);
        }

        return new SDJWTResult(processedVC, disclosures);
    }

    private static List<String> processSelectivePaths(
            Map<String, Object> vc, List<String> paths, String sdAlg) throws Exception {
        List<String> out = new ArrayList<>();
        for (String raw : paths) {
            String path = raw.trim();
            if (path.isEmpty()) {
                throw new Exception("empty path");
            }
            out.add(processSinglePath(vc, path, sdAlg));
        }
        return out;
    }

    private static String processSinglePath(Map<String, Object> vc, String path, String sdAlg)
            throws Exception {
        ResolvedTarget resolved = resolvePath(vc, path);
        if (resolved == null) {
            throw new Exception("path \"" + path + "\" not found");
        }
        return buildAndApplyDisclosure(resolved, sdAlg);
    }

    private static String buildAndApplyDisclosure(ResolvedTarget resolved, String sdAlg) throws Exception {
        String salt = SDJWT.randomSalt();
        List<Object> disclosureArr = buildDisclosureArray(resolved, salt);
        String disclosureJSON = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(disclosureArr);
        String encodedDisclosure = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(disclosureJSON.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String digest = SDJWT.hashDisclosure(sdAlg, encodedDisclosure);
        applyDisclosureToVC(resolved, digest);
        return encodedDisclosure;
    }

    private static List<Object> buildDisclosureArray(ResolvedTarget resolved, String salt) {
        return switch (resolved.kind) {
            case ObjectField, ArrayContainer -> List.of(salt, resolved.fieldName, resolved.value);
            case ArrayElem -> List.of(salt, resolved.value);
        };
    }

    @SuppressWarnings("unchecked")
    private static void applyDisclosureToVC(ResolvedTarget resolved, String digest) throws Exception {
        if (resolved.kind == TargetKind.ObjectField || resolved.kind == TargetKind.ArrayContainer) {
            Map<String, Object> m = (Map<String, Object>) resolved.parent;
            appendSD(m, digest);
            m.remove(resolved.fieldName);
            return;
        }
        if (resolved.kind == TargetKind.ArrayElem) {
            List<Object> arr = (List<Object>) resolved.parent;
            arr.set(resolved.index, SDJWT.newDisclosurePlaceholder(digest));
            if (resolved.parentMap != null && resolved.parentKey != null) {
                resolved.parentMap.put(resolved.parentKey, arr);
            }
            return;
        }
        throw new Exception("unexpected kind \"" + resolved.kind + "\"");
    }

    private static void processDecoys(
            Map<String, Object> vc, List<BuildDisclosuresInput.DecoyConfig> decoys, String sdAlg)
            throws Exception {
        for (BuildDisclosuresInput.DecoyConfig decoy : decoys) {
            if (decoy.count <= 0) {
                continue;
            }
            List<String> hashes = generateDecoyHashes(sdAlg, decoy.count);
            applyDecoyToVC(vc, decoy.path, hashes);
        }
    }

    @SuppressWarnings("unchecked")
    private static void applyDecoyToVC(Map<String, Object> vc, String path, List<String> hashes)
            throws Exception {
        ResolvedTarget resolved = resolvePath(vc, path);
        if (resolved == null) {
            return;
        }
        switch (resolved.kind) {
            case ObjectField -> applyDecoyToObjectField(resolved, hashes);
            case ArrayContainer -> applyDecoyToArrayContainer(resolved, hashes);
            case ArrayElem -> applyDecoyToArrayElement(resolved, hashes);
        }
    }

    @SuppressWarnings("unchecked")
    private static void applyDecoyToObjectField(ResolvedTarget resolved, List<String> hashes) {
        Map<String, Object> target;
        if (resolved.value instanceof Map<?, ?> map && !(resolved.value instanceof List<?>)) {
            target = (Map<String, Object>) resolved.value;
        } else {
            target = (Map<String, Object>) resolved.parent;
        }
        for (String h : hashes) {
            appendSD(target, h);
        }
    }

    @SuppressWarnings("unchecked")
    private static void applyDecoyToArrayContainer(ResolvedTarget resolved, List<String> hashes) {
        List<Object> arr = (List<Object>) resolved.value;
        Map<String, Object> parentMap = (Map<String, Object>) resolved.parent;
        List<Object> newArr = new ArrayList<>(arr);
        for (String h : hashes) {
            newArr.add(SDJWT.newDisclosurePlaceholder(h));
        }
        parentMap.put(resolved.fieldName, newArr);
    }

    @SuppressWarnings("unchecked")
    private static void applyDecoyToArrayElement(ResolvedTarget resolved, List<String> hashes) {
        if (hashes.isEmpty()) {
            return;
        }
        List<Object> arr = (List<Object>) resolved.parent;
        for (String h : hashes) {
            arr.add(SDJWT.newDisclosurePlaceholder(h));
        }
        if (resolved.parentMap != null && resolved.parentKey != null) {
            resolved.parentMap.put(resolved.parentKey, arr);
        }
    }

    @SuppressWarnings("unchecked")
    private static void appendSD(Map<String, Object> m, String digest) {
        Object existing = m.get("_sd");
        if (existing == null) {
            List<String> sd = new ArrayList<>();
            sd.add(digest);
            m.put("_sd", sd);
            return;
        }
        if (existing instanceof List<?> list) {
            ((List<String>) list).add(digest);
        }
    }

    @SuppressWarnings("unchecked")
    private static void shuffleSDArrays(Object node) {
        if (node instanceof List<?> list) {
            for (Object elem : list) {
                shuffleSDArrays(elem);
            }
            return;
        }
        if (node instanceof Map<?, ?> rawMap) {
            Map<String, Object> obj = (Map<String, Object>) rawMap;
            Object sd = obj.get("_sd");
            if (sd instanceof List<?> sdList) {
                List<String> arr = new ArrayList<>();
                for (Object x : sdList) {
                    if (x instanceof String s) {
                        arr.add(s);
                    }
                }
                for (int i = arr.size() - 1; i > 0; i--) {
                    int j = SHUFFLE_RANDOM.nextInt(i + 1);
                    String tmp = arr.get(i);
                    arr.set(i, arr.get(j));
                    arr.set(j, tmp);
                }
                obj.put("_sd", arr);
            }
            for (Object v : obj.values()) {
                shuffleSDArrays(v);
            }
        }
    }

    private static List<String> generateDecoyHashes(String sdAlg, int count) throws Exception {
        List<String> out = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            out.add(SDJWT.hashDisclosure(sdAlg, SDJWT.randomSalt()));
        }
        return out;
    }

    static final class PathSegment {
        String key;
        Integer index;
    }

    static final class ResolvedTarget {
        Object parent;
        Map<String, Object> parentMap;
        String parentKey;
        TargetKind kind;
        String fieldName;
        int index;
        Object value;
    }

    static List<PathSegment> parsePath(String path) throws Exception {
        String[] parts = path.split("\\.");
        List<PathSegment> segs = new ArrayList<>();
        for (String raw : parts) {
            String p = raw.trim();
            if (p.isEmpty()) {
                continue;
            }
            int bracketIdx = p.indexOf('[');
            if (bracketIdx == -1) {
                PathSegment seg = new PathSegment();
                seg.key = p;
                segs.add(seg);
                continue;
            }
            String key = p.substring(0, bracketIdx);
            String rest = p.substring(bracketIdx);
            if (!rest.endsWith("]")) {
                throw new Exception("invalid array segment \"" + p + "\" in path \"" + path + "\"");
            }
            String idxStr = rest.substring(1, rest.length() - 1);
            if (idxStr.isEmpty()) {
                throw new Exception("empty index in path \"" + path + "\"");
            }
            if ("*".equals(idxStr)) {
                throw new Exception("wildcard index '*' is not supported in path \"" + path + "\"");
            }
            int i;
            try {
                i = Integer.parseInt(idxStr);
            } catch (NumberFormatException e) {
                throw new Exception("invalid index \"" + idxStr + "\" in path \"" + path + "\"");
            }
            if (!String.valueOf(i).equals(idxStr)) {
                throw new Exception("invalid index \"" + idxStr + "\" in path \"" + path + "\"");
            }
            PathSegment seg = new PathSegment();
            seg.key = key;
            seg.index = i;
            segs.add(seg);
        }
        return segs;
    }

    @SuppressWarnings("unchecked")
    static ResolvedTarget resolvePath(Map<String, Object> root, String path) throws Exception {
        if (path.isEmpty()) {
            ResolvedTarget t = new ResolvedTarget();
            t.parent = root;
            t.kind = TargetKind.ObjectField;
            t.fieldName = "";
            return t;
        }
        List<PathSegment> segs = parsePath(path);
        if (segs.isEmpty()) {
            ResolvedTarget t = new ResolvedTarget();
            t.parent = root;
            t.kind = TargetKind.ObjectField;
            t.fieldName = "";
            return t;
        }

        Object current = root;
        for (int i = 0; i < segs.size(); i++) {
            PathSegment seg = segs.get(i);
            boolean last = i == segs.size() - 1;

            if (seg.index == null) {
                if (!(current instanceof Map<?, ?>)) {
                    throw new Exception("segment \"" + seg.key + "\" expects object");
                }
                Map<String, Object> m = (Map<String, Object>) current;
                if (!m.containsKey(seg.key)) {
                    return null;
                }
                Object val = m.get(seg.key);
                if (last) {
                    ResolvedTarget t = new ResolvedTarget();
                    t.parent = m;
                    t.fieldName = seg.key;
                    t.value = val;
                    if (val instanceof List<?>) {
                        t.kind = TargetKind.ArrayContainer;
                    } else {
                        t.kind = TargetKind.ObjectField;
                    }
                    return t;
                }
                current = val;
                continue;
            }

            List<Object> arr = resolveArray(current, seg, path);
            if (arr == null) {
                return null;
            }
            int idx = seg.index;
            if (idx < 0 || idx >= arr.size()) {
                throw new Exception(
                        "index " + idx + " out of range (len " + arr.size() + ") for path \"" + path + "\"");
            }
            if (last) {
                ResolvedTarget t = new ResolvedTarget();
                t.parent = arr;
                t.index = idx;
                t.value = arr.get(idx);
                t.kind = TargetKind.ArrayElem;
                if (seg.key != null && !seg.key.isEmpty()) {
                    t.parentMap = (Map<String, Object>) current;
                    t.parentKey = seg.key;
                }
                return t;
            }
            current = arr.get(idx);
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> resolveArray(Object current, PathSegment seg, String path) throws Exception {
        if (seg.key != null && !seg.key.isEmpty()) {
            if (!(current instanceof Map<?, ?>)) {
                throw new Exception("segment \"" + seg.key + "\" expects object");
            }
            Map<String, Object> m = (Map<String, Object>) current;
            if (!m.containsKey(seg.key)) {
                return null;
            }
            Object raw = m.get(seg.key);
            if (!(raw instanceof List<?>)) {
                throw new Exception("segment \"" + seg.key + "\" expects array");
            }
            return (List<Object>) raw;
        }
        if (!(current instanceof List<?>)) {
            throw new Exception("segment [" + seg.index + "] expects array");
        }
        return (List<Object>) current;
    }
}
