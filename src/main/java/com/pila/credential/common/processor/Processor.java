package com.pila.credential.common.processor;

import com.apicatalog.jsonld.JsonLd;
import com.apicatalog.jsonld.JsonLdOptions;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.uri.UriValidationPolicy;
import com.apicatalog.rdf.nquads.NQuadsWriter;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import jakarta.json.Json;
import jakarta.json.JsonReader;
import jakarta.json.JsonStructure;
import java.io.StringReader;
import java.io.StringWriter;

public class Processor {

    public static byte[] canonicalizeDocument(Map<String, Object> doc) throws Exception {
        if (doc == null) {
            throw new IllegalArgumentException("failed to canonicalize document: document is nil");
        }
        // "Compatible" canonicalizer: numbers/booleans are coerced to typed string
        // literals. Used ONLY to verify pre-existing legacy hex proofs (SDK <= v1.7.0).
        return canonicalizeStandardized(standardizeToJSONLD(doc));
    }

    /**
     * "Library" canonicalizer, go-credential-sdk's {@code Canonicalize}: native JSON number/boolean
     * types, undefined terms rejected, relative {@code @id}/{@code @type} rejected, empty output an
     * error. Used to sign and verify new proofs (ecdsa-rdfc-2019, EcdsaSecp256k1Signature2019). The
     * lenient {@link #canonicalizeDocument} is for verifying legacy proofs only.
     */
    public static byte[] canonicalizeDocumentNativeTypes(Map<String, Object> doc) throws Exception {
        if (doc == null) {
            throw new IllegalArgumentException("failed to canonicalize document: document is nil");
        }
        try {
            return JsonLdSdProcessor.canonicalize(doc);
        } catch (Exception e) {
            throw new Exception("failed to canonicalize document: " + e.getMessage(), e);
        }
    }

    private static byte[] canonicalizeStandardized(Map<String, Object> standardizedDoc) throws Exception {
        return JsonLdLimits.guard("canonicalize document", () -> {
            String json = new ObjectMapper().writeValueAsString(standardizedDoc);

            JsonStructure jsonStructure;
            try (JsonReader reader = Json.createReader(new StringReader(json))) {
                jsonStructure = reader.read();
            }
            JsonDocument document = JsonDocument.of(jsonStructure);

            // URI validation is disabled on purpose. Credentials issued by the Go SDK
            // (json-gold) carry types such as "IdentifyCredential" that no context defines,
            // which expand to relative IRIs. Titanium's default policy rejects those IRIs and
            // silently drops the statements - for such a credential the whole document
            // disappears and the signing input degrades to SHA-256 of an empty N-Quads set.
            // UriValidationPolicy.None keeps them, so this produces byte-for-byte the same
            // canonical N-Quads as json-gold and proofs verify across both SDKs.
            //
            // Like Go (which leaves SafeMode off here), undefined terms are NOT rejected: the legacy
            // canonicalizer stays lenient. Its loader is a fresh per-operation budget.
            JsonLdOptions options = ContextBudget.newOptions();
            options.setUriValidation(UriValidationPolicy.None);
            ContextBudget.limitInlineContexts(options, standardizedDoc);

            // RDFC canonicalizer, fed through the blank-node work cap.
            var canon = JsonLdLimits.canon(c -> JsonLd.toRdf(document).options(options).provide(c));

            StringWriter writer = new StringWriter();
            canon.provide(new NQuadsWriter(writer));
            return writer.toString().getBytes(StandardCharsets.UTF_8);
        });
    }

    /**
     * Go's {@code processor.WithDocumentLoader}: runs {@code body} with {@code loader} serving every
     * context that is not bundled (bundled W3C contexts stay offline). Applies to the calling thread only.
     */
    public static <T> T withDocumentLoader(com.apicatalog.jsonld.loader.DocumentLoader loader,
            java.util.concurrent.Callable<T> body) throws Exception {
        com.apicatalog.jsonld.loader.DocumentLoader prev = ContextBudget.LOADER_OVERRIDE.get();
        ContextBudget.LOADER_OVERRIDE.set(loader);
        try {
            return body.call();
        } finally {
            if (prev == null) {
                ContextBudget.LOADER_OVERRIDE.remove();
            } else {
                ContextBudget.LOADER_OVERRIDE.set(prev);
            }
        }
    }

    public static byte[] computeDigest(byte[] data) throws NoSuchAlgorithmException {
        if (data == null) {
            throw new IllegalArgumentException("failed to compute digest: input data is nil");
        }
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }

    private static Map<String, Object> standardizeToJSONLD(Map<String, Object> input) {
        Map<String, Object> result = new HashMap<>();
        for (Map.Entry<String, Object> entry : input.entrySet()) {
            result.put(entry.getKey(), convertToJSONLDCompatible(entry.getValue()));
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    private static Object convertToJSONLDCompatible(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof String) {
            return value;
        }
        if (value instanceof Map) {
            Map<String, Object> converted = new HashMap<>();
            Map<String, Object> mapValue = (Map<String, Object>) value;
            for (Map.Entry<String, Object> entry : mapValue.entrySet()) {
                converted.put(entry.getKey(), convertToJSONLDCompatible(entry.getValue()));
            }
            return converted;
        }
        if (value instanceof List) {
            List<Object> listValue = (List<Object>) value;
            List<Object> converted = new ArrayList<>(listValue.size());
            for (Object item : listValue) {
                converted.add(convertToJSONLDCompatible(item));
            }
            return converted;
        }
        if (value instanceof Number) {
            return buildTypedValue(goFloatV(((Number) value).doubleValue()), "http://www.w3.org/2001/XMLSchema#string");
        }
        if (value instanceof Boolean) {
            return buildTypedValue(value.toString(), "http://www.w3.org/2001/XMLSchema#boolean");
        }
        return buildTypedValue(value.toString(), "http://www.w3.org/2001/XMLSchema#string");
    }

    /**
     * Go's {@code fmt.Sprintf("%v", float64)}: shortest digits, exponent form when the decimal
     * exponent is below -4 or at least 6 ({@code 1e+06}, {@code 1.7e+09}, {@code 1e-05}).
     * Legacy VCs were signed from float64 values, so every JSON number goes through here.
     */
    /**
     * The shortest decimal that round-trips to {@code a} (> 0), like Go's {@code strconv} -1 precision.
     * {@code Double.toString} always prints two digits, so a one-digit shortest ({@code 5e-324}) is recovered here.
     */
    public static java.math.BigDecimal shortestDecimal(double a) {
        java.math.BigDecimal bd = new java.math.BigDecimal(Double.toString(a)).stripTrailingZeros();
        if (bd.precision() == 2) {
            java.math.BigDecimal one = bd.round(new java.math.MathContext(1, java.math.RoundingMode.HALF_EVEN));
            if (one.doubleValue() == a) {
                return one.stripTrailingZeros();
            }
        }
        return bd;
    }

    static String goFloatV(double d) {
        if (d == 0) {
            return 1 / d < 0 ? "-0" : "0";
        }
        java.math.BigDecimal bd = shortestDecimal(Math.abs(d));
        String digits = bd.unscaledValue().toString();
        int nd = digits.length();
        int dp = nd - bd.scale();
        int exp = dp - 1;
        StringBuilder sb = new StringBuilder(d < 0 ? "-" : "");
        if (exp < -4 || exp >= 6) {
            sb.append(digits.charAt(0));
            if (nd > 1) {
                sb.append('.').append(digits, 1, nd);
            }
            sb.append('e').append(exp < 0 ? '-' : '+');
            int ae = Math.abs(exp);
            if (ae < 10) {
                sb.append('0');
            }
            return sb.append(ae).toString();
        }
        if (dp <= 0) {
            return sb.append("0.").append("0".repeat(-dp)).append(digits).toString();
        }
        if (dp >= nd) {
            return sb.append(digits).append("0".repeat(dp - nd)).toString();
        }
        return sb.append(digits, 0, dp).append('.').append(digits, dp, nd).toString();
    }

    private static Map<String, Object> buildTypedValue(String value, String type) {
        Map<String, Object> result = new HashMap<>();
        result.put("@value", value);
        result.put("@type", type);
        return result;
    }

    /** ecdsa-sd-2023 canonical N-Quads with blank-node id map (URDNA2015). */
    public static JsonLdSdProcessor.CanonicalizeResult canonicalizeWithIdMap(Map<String, Object> doc) throws Exception {
        return JsonLdSdProcessor.canonicalizeWithIdMap(doc);
    }

    /** ecdsa-sd-2023 canonical bytes (native JSON types, SafeMode). */
    public static byte[] canonicalizeForSd(Map<String, Object> doc) throws Exception {
        return JsonLdSdProcessor.canonicalize(doc);
    }

    public static JsonLdSdProcessor.CanonicalizeResult canonicalizeNQuadsWithIdMap(List<String> nquads)
            throws Exception {
        return JsonLdSdProcessor.canonicalizeNQuadsWithIdMap(nquads);
    }

    public static List<Object> expandJsonLd(Map<String, Object> doc) throws Exception {
        return JsonLdSdProcessor.expandJsonLd(doc);
    }

    public static Map<String, Object> compactJsonLd(List<Object> expanded, Object context) throws Exception {
        return JsonLdSdProcessor.compactJsonLd(expanded, context);
    }

    public static List<String> toRdfNQuads(Object doc) throws Exception {
        return JsonLdSdProcessor.toRdfNQuads(doc);
    }
}