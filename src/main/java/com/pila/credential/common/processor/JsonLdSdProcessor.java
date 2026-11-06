package com.pila.credential.common.processor;

import com.apicatalog.jsonld.JsonLd;
import com.apicatalog.jsonld.JsonLdOptions;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.rdf.canon.RdfCanon;
import com.apicatalog.rdf.nquads.NQuadsReader;
import com.apicatalog.rdf.nquads.NQuadsWriter;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.JsonStructure;
import jakarta.json.JsonValue;

import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * JSON-LD canonicalization for ecdsa-sd-2023 (preserves native JSON types, SafeMode).
 */
public final class JsonLdSdProcessor {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private JsonLdSdProcessor() {
    }

    public record CanonicalizeResult(List<String> nquads, Map<String, String> idMap) {
    }

    public static byte[] canonicalize(Map<String, Object> doc) throws Exception {
        List<String> nquads = canonicalizeNQuads(doc);
        String joined = String.join("", nquads);
        if (joined.isEmpty()) {
            throw new Exception(
                    "canonicalization produced no N-Quads; the document has no @context or no JSON-LD terms");
        }
        return joined.getBytes(StandardCharsets.UTF_8);
    }

    public static List<String> canonicalizeNQuads(Map<String, Object> doc) throws Exception {
        return canonicalizeWithIdMap(doc).nquads();
    }

    public static CanonicalizeResult canonicalizeWithIdMap(Map<String, Object> doc) throws Exception {
        if (doc == null) {
            throw new IllegalArgumentException("canonicalize: document is nil");
        }
        return JsonLdLimits.guard("canonicalize", () -> canonicalizeDocumentWithIdMap(toDocument(expandJsonLd(doc))));
    }

    public static CanonicalizeResult canonicalizeNQuadsWithIdMap(List<String> nquads) throws Exception {
        String input = String.join("", nquads);
        return JsonLdLimits.guard("canonicalize", () ->
                writeCanonResult(JsonLdLimits.canon(c -> new NQuadsReader(new StringReader(input)).provide(c))));
    }

    @SuppressWarnings("unchecked")
    public static List<Object> expandJsonLd(Map<String, Object> doc) throws Exception {
        return JsonLdLimits.guard("expand", () -> {
            Map<String, Object> std = preserveNativeTypes(doc);
            JsonDocument document = toDocument(std);
            JsonLdOptions opts = sdOptions();
            ContextBudget.limitInlineContexts(opts, std);
            JsonArray expanded = JsonLd.expand(document).options(opts).get();
            List<Object> out = MAPPER.readValue(expanded.toString(), new TypeReference<>() {
            });
            checkExpandedTypes(out);
            rejectRelativeIds(out);
            return out;
        });
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> compactJsonLd(List<Object> expanded, Object context) throws Exception {
        return JsonLdLimits.guard("compact", () -> {
            JsonDocument expandedDoc = toDocument(expanded);
            JsonDocument ctxDoc = contextDocument(context);
            JsonObject compact = JsonLd.compact(expandedDoc, ctxDoc).options(sdOptions()).get();
            return MAPPER.readValue(compact.toString(), new TypeReference<>() {
            });
        });
    }

    public static List<String> toRdfNQuads(Object doc) throws Exception {
        return JsonLdLimits.guard("to rdf", () -> {
            JsonDocument document = toDocument(doc);
            JsonLdOptions opts = sdOptions();
            ContextBudget.limitInlineContexts(opts, doc);
            StringWriter writer = new StringWriter();
            JsonLd.toRdf(document).options(opts).provide(new NQuadsWriter(writer));
            return splitNQuadsKeepNl(writer.toString());
        });
    }

    private static CanonicalizeResult canonicalizeDocumentWithIdMap(JsonDocument document) throws Exception {
        JsonLdOptions opts = sdOptions();
        // The input is already expanded (expandJsonLd limited its inline contexts); remote ones go through opts' budget.
        return writeCanonResult(JsonLdLimits.canon(c -> JsonLd.toRdf(document).options(opts).provide(c)));
    }

    private static CanonicalizeResult writeCanonResult(RdfCanon canon) throws Exception {
        StringWriter writer = new StringWriter();
        canon.provide(new NQuadsWriter(writer));
        List<String> nquads = splitNQuadsKeepNl(writer.toString());
        Map<String, String> idMap = canon.mapping();
        return new CanonicalizeResult(nquads, idMap != null ? idMap : Map.of());
    }

    static JsonLdOptions sdOptions() {
        JsonLdOptions opts = ContextBudget.newOptions();
        opts.setUndefinedTermsPolicy(JsonLdOptions.ProcessingPolicy.Fail);
        return opts;
    }

    static JsonDocument toDocument(Object value) throws Exception {
        String json = MAPPER.writeValueAsString(value);
        try (JsonReader reader = Json.createReader(new StringReader(json))) {
            JsonStructure structure = reader.read();
            return JsonDocument.of(structure);
        }
    }

    private static JsonDocument contextDocument(Object context) throws Exception {
        if (context instanceof String s) {
            try (JsonReader reader = Json.createReader(new StringReader(s))) {
                return JsonDocument.of(reader.read());
            }
        }
        return toDocument(context);
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> preserveNativeTypes(Map<String, Object> input) {
        Map<String, Object> out = new HashMap<>(input.size());
        for (Map.Entry<String, Object> e : input.entrySet()) {
            out.put(e.getKey(), preserveNativeTypesValue(e.getValue()));
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static Object preserveNativeTypesValue(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> out = new HashMap<>();
            for (Map.Entry<?, ?> e : map.entrySet()) {
                out.put(String.valueOf(e.getKey()), preserveNativeTypesValue(e.getValue()));
            }
            return out;
        }
        if (value instanceof List<?> list) {
            List<Object> out = new ArrayList<>(list.size());
            for (Object item : list) {
                out.add(preserveNativeTypesValue(item));
            }
            return out;
        }
        if (value instanceof Number n) {
            // Go decodes every JSON number into float64 (so 2^53+1 loses its low bit) and json-gold
            // then types an integral value below 1e21 as xsd:integer and the rest as xsd:double.
            double d = n.doubleValue();
            if (d == Math.rint(d) && Math.abs(d) < 1e21) {
                return new java.math.BigDecimal(d).toBigInteger();
            }
            return d;
        }
        return value;
    }

    static List<String> splitNQuadsKeepNl(String s) {
        if (s == null || s.isEmpty()) {
            return List.of();
        }
        String[] parts = s.split("(?<=\n)");
        List<String> out = new ArrayList<>();
        for (String part : parts) {
            if (!part.trim().isEmpty()) {
                if (!part.endsWith("\n")) {
                    part = part + "\n";
                }
                out.add(part);
            }
        }
        return out;
    }

    private static void checkExpandedTypes(List<Object> expanded) throws Exception {
        List<String> dropped = relativeKeywordValues(expanded, "@type");
        if (!dropped.isEmpty()) {
            throw new Exception("json-ld: type \"" + dropped.get(0)
                    + "\" is not defined by @context and would be dropped, leaving it unsigned");
        }
    }

    private static void rejectRelativeIds(List<Object> expanded) throws Exception {
        List<String> dropped = relativeKeywordValues(expanded, "@id");
        if (!dropped.isEmpty()) {
            throw new Exception("json-ld: id \"" + dropped.get(0)
                    + "\" is not an absolute IRI and would be dropped, leaving the node unsigned");
        }
    }

    @SuppressWarnings("unchecked")
    private static List<String> relativeKeywordValues(Object value, String keyword) {
        List<String> out = new ArrayList<>();
        collectRelativeKeywordValues(value, keyword, out);
        return out;
    }

    @SuppressWarnings("unchecked")
    private static void collectRelativeKeywordValues(Object value, String keyword, List<String> out) {
        if (value instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> e : map.entrySet()) {
                String key = String.valueOf(e.getKey());
                if (!keyword.equals(key)) {
                    collectRelativeKeywordValues(e.getValue(), keyword, out);
                    continue;
                }
                for (Object kv : arrayify(e.getValue())) {
                    if (kv instanceof String s && isRelativeIri(s)) {
                        out.add(s);
                    }
                }
            }
        } else if (value instanceof List<?> list) {
            for (Object item : list) {
                collectRelativeKeywordValues(item, keyword, out);
            }
        }
    }

    private static List<Object> arrayify(Object value) {
        if (value instanceof List<?> list) {
            return new ArrayList<>(list);
        }
        List<Object> single = new ArrayList<>(1);
        single.add(value);
        return single;
    }

    private static final java.util.Set<String> KEYWORDS = java.util.Set.of("@base", "@container", "@context",
            "@default", "@direction", "@embed", "@explicit", "@json", "@id", "@included", "@index", "@first",
            "@graph", "@import", "@language", "@list", "@nest", "@none", "@omitDefault", "@prefix", "@preserve",
            "@propagate", "@protected", "@requireAll", "@reverse", "@set", "@type", "@value", "@version", "@vocab");
    private static final java.util.regex.Pattern SCHEME = java.util.regex.Pattern.compile("^[A-Za-z][A-Za-z0-9+.\\-]*:");

    /**
     * json-gold's {@code IsRelativeIri}: neither a keyword nor absolute, where absolute means a blank
     * node label or something Go's {@code url.Parse} accepts with a scheme (so {@code ""} is relative
     * and a colon alone does not make an IRI absolute).
     */
    static boolean isRelativeIri(String s) {
        if (s == null || KEYWORDS.contains(s)) {
            return false;
        }
        if (s.startsWith("_:")) {
            return false;
        }
        return !(SCHEME.matcher(s).find() && parsesAsUrl(s));
    }

    /** The cases where url.Parse errors: control characters, malformed percent escapes, bad host characters. */
    private static boolean parsesAsUrl(String s) {
        int slashes = s.indexOf("//");
        if (slashes >= 0 && SCHEME.matcher(s.substring(0, slashes)).matches()) {
            int end = s.length();
            for (int k = slashes + 2; k < s.length(); k++) {
                if ("/?#".indexOf(s.charAt(k)) >= 0) {
                    end = k;
                    break;
                }
            }
            String authority = s.substring(slashes + 2, end);
            for (int k = 0; k < authority.length(); k++) {
                if (" <>\"\\^`{|}".indexOf(authority.charAt(k)) >= 0) {
                    return false;
                }
            }
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x20 || c == 0x7f) {
                return false;
            }
            if (c == '%' && (i + 2 >= s.length() || Character.digit(s.charAt(i + 1), 16) < 0
                    || Character.digit(s.charAt(i + 2), 16) < 0)) {
                return false;
            }
        }
        return true;
    }
}
