package com.pila.credential.common.processor;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Expected values observed by running go-credential-sdk (go-fixtures/go-facts.json). */
class GoCanonicalizationFactsTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static JsonNode facts;

    @BeforeAll
    static void load() throws Exception {
        try (InputStream in = GoCanonicalizationFactsTest.class.getResourceAsStream("/go-fixtures/go-facts.json")) {
            facts = MAPPER.readTree(in);
        }
    }

    private static Map<String, Object> doc(JsonNode n) throws Exception {
        return MAPPER.convertValue(n, new TypeReference<Map<String, Object>>() {
        });
    }

    /** 2.3: the legacy canonicalizer renders numbers with Go's %v on float64. */
    @Test
    void legacyCanonicalizerFormatsNumbersLikeGoPercentV() throws Exception {
        String got = new String(Processor.canonicalizeDocument(doc(facts.get("doc"))), StandardCharsets.UTF_8);
        assertEquals(facts.get("legacy").asText(), got);
    }

    /** 2.4: the library canonicalizer sends every number through float64 and types it integer/double. */
    @Test
    void libraryCanonicalizerMatchesGoNumberTyping() throws Exception {
        String got = new String(Processor.canonicalizeDocumentNativeTypes(doc(facts.get("doc"))), StandardCharsets.UTF_8);
        assertEquals(facts.get("library").asText(), got);
    }

    /** 2.1: undefined terms, relative ids and an empty dataset are errors for new proofs, never for legacy ones. */
    @Test
    void libraryCanonicalizerIsSafeLegacyStaysLenient() throws Exception {
        Map<String, Object> noContext = Map.of("issuer", "did:example:i", "type", java.util.List.of("VerifiableCredential"));
        assertThrows(Exception.class, () -> Processor.canonicalizeDocumentNativeTypes(noContext));
        Processor.canonicalizeDocument(noContext);

        Map<String, Object> relativeId = MAPPER.readValue("""
                {"@context":["https://www.w3.org/ns/credentials/v2"],"id":"rel/1",
                 "type":["VerifiableCredential"],"issuer":"did:example:i"}""", new TypeReference<>() {
        });
        Exception e = assertThrows(Exception.class, () -> Processor.canonicalizeDocumentNativeTypes(relativeId));
        assertTrue(e.getMessage().contains("rel/1"), e.getMessage());
        Processor.canonicalizeDocument(relativeId);

        Map<String, Object> undefined = MAPPER.readValue("""
                {"@context":["https://www.w3.org/ns/credentials/v2"],"id":"urn:uuid:1","type":["VerifiableCredential"],
                 "issuer":"did:example:i","renderMethod":{"id":"https://e.com/r","type":"SuiteRenderMethod",
                 "renderSuite":"html","renderProperty":["/x"]}}""", new TypeReference<>() {
        });
        assertThrows(Exception.class, () -> Processor.canonicalizeDocumentNativeTypes(undefined));
        Processor.canonicalizeDocument(undefined);

        Map<String, Object> empty = Map.of("@context", Map.of("@vocab", "https://ex.org/#"));
        Exception ee = assertThrows(Exception.class, () -> Processor.canonicalizeDocumentNativeTypes(empty));
        assertTrue(ee.getMessage().contains("no N-Quads"), ee.getMessage());
        assertEquals(0, Processor.canonicalizeDocument(empty).length);
    }

    /** 2.12: json-gold's IsRelativeIri decides, case by case. */
    @Test
    void relativeIriMatchesGo() {
        Iterator<Map.Entry<String, JsonNode>> it = facts.get("relativeIri").fields();
        while (it.hasNext()) {
            Map.Entry<String, JsonNode> e = it.next();
            assertEquals(e.getValue().asBoolean(), JsonLdSdProcessor.isRelativeIri(e.getKey()), "'" + e.getKey() + "'");
        }
    }

    /** 2.8: security v1/v2 and the secp256k1 suite context resolve from the classpath, no network. */
    @Test
    void securityContextsAreBundled() throws Exception {
        for (String u : new String[] {"https://w3id.org/security/v1", "https://w3id.org/security/v2",
                "https://w3id.org/security/suites/secp256k1-2019/v1"}) {
            byte[] b = LocalContextDocumentLoader.localBytes(URI.create(u));
            assertNotNull(b, u);
            assertTrue(MAPPER.readTree(b).has("@context"), u);
        }
    }

    /** 2.10: a per-call loader serves contexts that are not bundled. */
    @Test
    void withDocumentLoaderServesCustomContext() throws Exception {
        Map<String, Object> d = Map.of("@context", "https://contexts.invalid/c1", "id", "urn:x:1", "name", "a");
        assertThrows(Exception.class, () -> Processor.canonicalizeDocumentNativeTypes(d));
        byte[] out = Processor.withDocumentLoader((url, opts) -> LocalContextDocumentLoader.documentOf(url,
                "{\"@context\":{\"id\":\"@id\",\"name\":\"https://ex.org/name\"}}".getBytes(StandardCharsets.UTF_8)),
                () -> Processor.canonicalizeDocumentNativeTypes(d));
        assertTrue(new String(out, StandardCharsets.UTF_8).contains("<https://ex.org/name> \"a\""));
    }
}
