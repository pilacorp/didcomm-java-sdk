package com.pila.credential.common.ecdsasd;

import com.pila.credential.common.processor.JsonLdSdProcessor;
import com.pila.credential.common.processor.Processor;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class LabelMap {

    private static final Pattern URN_BNID = Pattern.compile("<urn:bnid:([^>]+)>");
    private static final Pattern BNODE = Pattern.compile("_:([^\\s]+)");

    private LabelMap() {
    }

    public static final class GroupIndexes {
        public final Map<Integer, String> matching = new HashMap<>();
        public final Map<Integer, String> nonMatching = new HashMap<>();
        public final List<String> deskolemizedNQuads = new ArrayList<>();
    }

    public static final class GroupedCanon {
        public List<String> hmacNQuads;
        public Map<String, String> labelMap;
        public Map<String, String> inputToCanonical = new HashMap<>();
        public Map<String, Object> skolemizedCompact;
        public Map<String, GroupIndexes> groups = new HashMap<>();
    }

    public static GroupedCanon canonicalizeAndGroup(Map<String, Object> document, byte[] hmacKey,
            Map<String, List<String>> groups) throws Exception {
        SkolemResult sk = skolemizeCompactJsonLd(document);
        List<String> deskolemized = toDeskolemizedNQuads(sk.expanded());
        LabelReplacementResult lr = labelReplacementCanonicalizeNQuads(deskolemized, hmacKey);

        GroupedCanon result = new GroupedCanon();
        result.hmacNQuads = lr.relabeled();
        result.labelMap = lr.labelMap();
        result.inputToCanonical = lr.inputToCanonical();
        result.skolemizedCompact = sk.compact();

        for (Map.Entry<String, List<String>> entry : groups.entrySet()) {
            SelectNQuadsResult sel = selectCanonicalNQuads(sk.compact(), entry.getValue(), lr.labelMap());
            Set<String> selSet = new HashSet<>(sel.relabeled());
            GroupIndexes gi = new GroupIndexes();
            gi.deskolemizedNQuads.addAll(sel.deskolemized());
            for (int idx = 0; idx < lr.relabeled().size(); idx++) {
                String nq = lr.relabeled().get(idx);
                if (selSet.contains(nq)) {
                    gi.matching.put(idx, nq);
                } else {
                    gi.nonMatching.put(idx, nq);
                }
            }
            result.groups.put(entry.getKey(), gi);
        }
        return result;
    }

    public static List<String> relabelBlankNodes(List<String> nquads, Map<String, String> labelMap) {
        List<String> out = new ArrayList<>(nquads.size());
        for (String nq : nquads) {
            Matcher m = BNODE.matcher(nq);
            StringBuffer sb = new StringBuffer();
            while (m.find()) {
                String label = m.group(1);
                String repl = labelMap.getOrDefault(label, label);
                m.appendReplacement(sb, "_:" + Matcher.quoteReplacement(repl));
            }
            m.appendTail(sb);
            out.add(sb.toString());
        }
        return out;
    }

    private record SkolemResult(List<Object> expanded, Map<String, Object> compact) {
    }

    private record LabelReplacementResult(List<String> relabeled, Map<String, String> labelMap,
            Map<String, String> inputToCanonical) {
    }

    private record SelectNQuadsResult(List<String> deskolemized, List<String> relabeled) {
    }

    private static SkolemResult skolemizeCompactJsonLd(Map<String, Object> document) throws Exception {
        List<Object> expanded = Processor.expandJsonLd(document);
        byte[] random = new byte[16];
        new SecureRandom().nextBytes(random);
        String randomHex = hex(random);
        SkolemLabeler labeler = new SkolemLabeler("urn:bnid:", randomHex);
        List<Object> skolemized = skolemizeExpanded(expanded, labeler);
        Map<String, Object> compact = Processor.compactJsonLd(skolemized, document.get("@context"));
        return new SkolemResult(skolemized, compact);
    }

    @SuppressWarnings("unchecked")
    private static List<Object> skolemizeExpanded(List<Object> expanded, SkolemLabeler labeler) {
        List<Object> out = new ArrayList<>(expanded.size());
        for (Object element : expanded) {
            if (!(element instanceof Map<?, ?> m)) {
                out.add(Helpers.deepCopy(element));
                continue;
            }
            if (m.containsKey("@value")) {
                out.add(Helpers.deepCopy(element));
                continue;
            }
            Map<String, Object> node = new HashMap<>();
            for (Map.Entry<?, ?> e : m.entrySet()) {
                String prop = String.valueOf(e.getKey());
                Object value = e.getValue();
                if (value instanceof List<?> arr) {
                    node.put(prop, skolemizeExpanded(new ArrayList<>(arr), labeler));
                } else {
                    node.put(prop, skolemizeExpanded(List.of(value), labeler).get(0));
                }
            }
            Object id = node.get("@id");
            if (!(id instanceof String idStr)) {
                node.put("@id", labeler.prefix + "_" + labeler.random + "_" + labeler.count++);
            } else if (idStr.startsWith("_:")) {
                node.put("@id", labeler.prefix + idStr.substring(2));
            }
            out.add(node);
        }
        return out;
    }

    private static final class SkolemLabeler {
        final String prefix;
        final String random;
        int count;

        SkolemLabeler(String prefix, String random) {
            this.prefix = prefix;
            this.random = random;
        }
    }

    private static List<String> toDeskolemizedNQuads(Object document) throws Exception {
        return deskolemizeNQuads(Processor.toRdfNQuads(document));
    }

    private static List<String> deskolemizeNQuads(List<String> nquads) {
        List<String> out = new ArrayList<>(nquads.size());
        for (String nq : nquads) {
            if (nq.contains("<urn:bnid:")) {
                out.add(URN_BNID.matcher(nq).replaceAll("_:$1"));
            } else {
                out.add(nq);
            }
        }
        return out;
    }

    private static LabelReplacementResult labelReplacementCanonicalizeNQuads(List<String> nquads, byte[] hmacKey)
            throws Exception {
        JsonLdSdProcessor.CanonicalizeResult canon = Processor.canonicalizeNQuadsWithIdMap(nquads);
        Map<String, String> canonicalIdMap = new HashMap<>();
        for (Map.Entry<String, String> e : canon.idMap().entrySet()) {
            canonicalIdMap.put(stripBnode(e.getKey()), stripBnode(e.getValue()));
        }
        Map<String, String> labelMap = createHmacLabelMap(canonicalIdMap, hmacKey);
        Map<String, String> c14nToNew = new HashMap<>();
        for (Map.Entry<String, String> e : labelMap.entrySet()) {
            c14nToNew.put(canonicalIdMap.get(e.getKey()), e.getValue());
        }
        List<String> out = new ArrayList<>(relabelBlankNodes(canon.nquads(), c14nToNew));
        out.sort(String::compareTo);
        return new LabelReplacementResult(out, labelMap, canonicalIdMap);
    }

    private static Map<String, String> createHmacLabelMap(Map<String, String> canonicalIdMap, byte[] hmacKey)
            throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
        Map<String, String> out = new HashMap<>();
        for (Map.Entry<String, String> e : canonicalIdMap.entrySet()) {
            mac.reset();
            mac.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
            byte[] digest = mac.doFinal(e.getValue().getBytes(StandardCharsets.UTF_8));
            out.put(e.getKey(), "u" + Base64.getUrlEncoder().withoutPadding().encodeToString(digest));
        }
        return out;
    }

    private static SelectNQuadsResult selectCanonicalNQuads(Map<String, Object> compact, List<String> pointers,
            Map<String, String> labelMap) throws Exception {
        Map<String, Object> selection = Pointer.selectJsonLd(compact, pointers);
        if (selection == null) {
            return new SelectNQuadsResult(List.of(), List.of());
        }
        List<String> deskolemized = toDeskolemizedNQuads(selection);
        return new SelectNQuadsResult(deskolemized, relabelBlankNodes(deskolemized, labelMap));
    }

    private static String stripBnode(String label) {
        return label.startsWith("_:") ? label.substring(2) : label;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte value : b) {
            sb.append(String.format("%02x", value));
        }
        return sb.toString();
    }
}
