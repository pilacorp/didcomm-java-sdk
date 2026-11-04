package com.pila.credential.common.processor;

import com.apicatalog.jsonld.JsonLd;
import com.apicatalog.jsonld.JsonLdOptions;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.uri.UriValidationPolicy;
import com.apicatalog.rdf.nquads.NQuadsWriter;

import com.apicatalog.rdf.canon.RdfCanon;
import com.apicatalog.rdf.canon.RdfCanonTimeTicker;
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
     * "Library" canonicalizer: native JSON number/boolean types are preserved, matching
     * go-credential-sdk's {@code Canonicalize}. Used to sign and verify new proofs
     * (ecdsa-rdfc-2019, EcdsaSecp256k1Signature2019). Shares the lenient JSON-LD options
     * of {@link #canonicalizeDocument} so Go-issued terms that expand to relative IRIs are
     * kept rather than dropped. A numeric claim signed with the compatible canonicalizer
     * would not interoperate with Go.
     */
    public static byte[] canonicalizeDocumentNativeTypes(Map<String, Object> doc) throws Exception {
        if (doc == null) {
            throw new IllegalArgumentException("failed to canonicalize document: document is nil");
        }
        return canonicalizeStandardized(JsonLdSdProcessor.preserveNativeTypes(doc));
    }

    private static byte[] canonicalizeStandardized(Map<String, Object> standardizedDoc) throws Exception {
        String json = new ObjectMapper().writeValueAsString(standardizedDoc);

        JsonStructure jsonStructure;
        try (JsonReader reader = Json.createReader(new StringReader(json))) {
            jsonStructure = reader.read();
        }
        JsonDocument document = JsonDocument.of(jsonStructure);

        // 1) Create RDFC canonicalizer
        var canon = RdfCanon.create("SHA-256", new RdfCanonTimeTicker(5 * 1000));

        // 2) Provide RDF from JSON-LD to canonicalizer using local context loader.
        //
        // URI validation is disabled on purpose. Credentials issued by the Go SDK
        // (json-gold) carry types such as "IdentifyCredential" that no context defines,
        // which expand to relative IRIs. Titanium's default policy rejects those IRIs and
        // silently drops the statements - for such a credential the whole document
        // disappears and the signing input degrades to SHA-256 of an empty N-Quads set.
        // UriValidationPolicy.None keeps them, so this produces byte-for-byte the same
        // canonical N-Quads as json-gold and proofs verify across both SDKs.
        JsonLdOptions options = new JsonLdOptions();
        options.setDocumentLoader(new LocalContextDocumentLoader());
        options.setUriValidation(UriValidationPolicy.None);

        JsonLd.toRdf(document)
                .options(options)
                .provide(canon);

        // 3) Write canonical N-Quads to writer
        StringWriter writer = new StringWriter();
        canon.provide(new NQuadsWriter(writer));

        // 4) Hash canonical N-Quads
        return writer.toString().getBytes(StandardCharsets.UTF_8);
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
            return buildTypedValue(value.toString(), "http://www.w3.org/2001/XMLSchema#string");
        }
        if (value instanceof Boolean) {
            return buildTypedValue(value.toString(), "http://www.w3.org/2001/XMLSchema#boolean");
        }
        return buildTypedValue(value.toString(), "http://www.w3.org/2001/XMLSchema#string");
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