package com.pila.credential.vc;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.processor.Processor;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class W3cRenderMethodCanonicalizationTest {

    private static final String RENDER_IRI = "https://www.w3.org/2018/credentials#renderMethod";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String WITH_EXAMPLES = """
            {
              "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
              ],
              "id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
              "type": ["VerifiableCredential"],
              "issuer": "did:example:issuer",
              "credentialSubject": {"id": "did:example:subject", "name": "Alice"},
              "renderMethod": {
                "id": "https://example.com/render-method",
                "type": "SuiteRenderMethod",
                "renderSuite": "html",
                "renderProperty": ["/credentialSubject/name"],
                "template": {
                  "id": "https://example.com/templates/name.html",
                  "mediaType": "text/html"
                }
              }
            }
            """;

    private static final String V2_ONLY = """
            {
              "@context": ["https://www.w3.org/ns/credentials/v2"],
              "id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
              "type": ["VerifiableCredential"],
              "issuer": "did:example:issuer",
              "credentialSubject": {"id": "did:example:subject", "name": "Alice"},
              "renderMethod": {
                "id": "https://example.com/render-method",
                "type": "SuiteRenderMethod",
                "renderSuite": "html",
                "renderProperty": ["/credentialSubject/name"],
                "template": {
                  "id": "https://example.com/templates/name.html",
                  "mediaType": "text/html"
                }
              }
            }
            """;

    @Test
    void bundledW3cV2ContextDefinesRenderMethod() throws Exception {
        try (InputStream in = getClass().getResourceAsStream("/contexts/w3c.credential.v2.json")) {
            JsonNode term = MAPPER.readTree(in)
                    .path("@context")
                    .path("VerifiableCredential")
                    .path("@context")
                    .path("renderMethod");
            assertEquals(RENDER_IRI, term.path("@id").asText());
            assertEquals("@id", term.path("@type").asText());
        }
    }

    @Test
    void canonicalizePreservesRenderMethodWithExamplesContext() throws Exception {
        Map<String, Object> doc = MAPPER.readValue(WITH_EXAMPLES, new TypeReference<>() {});
        String nquads = new String(Processor.canonicalizeDocument(doc), StandardCharsets.UTF_8);
        assertTrue(nquads.contains("<" + RENDER_IRI + ">"));
        assertTrue(nquads.contains("https://www.w3.org/ns/credentials/examples#SuiteRenderMethod"));
        assertTrue(nquads.contains("https://www.w3.org/ns/credentials/examples#renderSuite"));

        JSONCredential cred = JSONCredential.parseJSONCredential(WITH_EXAMPLES.getBytes(StandardCharsets.UTF_8));
        assertEquals(32, cred.getSigningInput().length);
    }

    @Test
    void canonicalizeWithV2OnlyStillProducesRenderMethodTriple() throws Exception {
        Map<String, Object> doc = MAPPER.readValue(V2_ONLY, new TypeReference<>() {});
        String nquads = new String(Processor.canonicalizeDocument(doc), StandardCharsets.UTF_8);
        assertTrue(nquads.contains("<" + RENDER_IRI + ">"));

        JSONCredential cred = JSONCredential.parseJSONCredential(V2_ONLY.getBytes(StandardCharsets.UTF_8));
        assertEquals(32, cred.getSigningInput().length);
    }
}
