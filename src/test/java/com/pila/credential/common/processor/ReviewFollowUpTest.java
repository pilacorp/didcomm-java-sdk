package com.pila.credential.common.processor;

import static org.junit.jupiter.api.Assertions.*;

import com.pila.credential.common.schema.JsonSchemaValidator;
import com.pila.credential.common.util.Rfc3339;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.format.DateTimeParseException;
import java.util.Map;

class ReviewFollowUpTest {
    @Test
    void doubleLexicalMatchesJsonGold() {
        assertEquals("3.103636273531341E3", JsonLdSdProcessor.goDoubleLexical(3103.6362735313405));
        assertEquals("1.0E20", JsonLdSdProcessor.goDoubleLexical(1e20));
        assertEquals("-2.5E-5", JsonLdSdProcessor.goDoubleLexical(-0.000025));
    }

    @Test
    void rfc3339IsStrict() {
        assertThrows(DateTimeParseException.class, () -> Rfc3339.parse("2024-01-01T00:00Z"));
        assertThrows(DateTimeParseException.class, () -> Rfc3339.parse("2024-01-01T00:00:00+01:00:30"));
        assertNotNull(Rfc3339.parse("2024-01-01T00:00:00Z"));
    }

    @Test
    void schemaFormatAndRegexBudget() throws Exception {
        byte[] fmt = "{\"type\":\"string\",\"format\":\"date-time\"}".getBytes(StandardCharsets.UTF_8);
        assertFalse(JsonSchemaValidator.validate(fmt, "nope").isEmpty());
        assertTrue(JsonSchemaValidator.validate(fmt, "2024-01-01T00:00:00Z").isEmpty());
        byte[] evil = "{\"type\":\"string\",\"pattern\":\"(.*a){25}x\"}".getBytes(StandardCharsets.UTF_8);
        assertFalse(JsonSchemaValidator.validate(evil, "a".repeat(40)).isEmpty()); // no match, and no stall
    }

    /** Expected N-Quads are the output of go-credential-sdk's processor.Canonicalize (6cd59d4) for this input. */
    @Test
    void nativeNumbersCanonicalizeLikeGo() throws Exception {
        Map<String, Object> doc = new com.fasterxml.jackson.databind.ObjectMapper().readValue(
                "{\"@context\":{\"@vocab\":\"http://ex.org/\",\"c\":{\"@id\":\"http://ex.org/c\","
                        + "\"@type\":\"http://www.w3.org/2001/XMLSchema#string\"}},\"@id\":\"http://ex.org/s\","
                        + "\"a\":3103.6362735313405,\"b\":1e20,\"c\":1.5,\"d\":0.00001,\"e\":123456789012345678,"
                        + "\"f\":1e300,\"g\":-2.5,\"h\":100,\"i\":1e21}",
                new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {
                });
        String x = "^^<http://www.w3.org/2001/XMLSchema#";
        String s = "<http://ex.org/s> <http://ex.org/";
        String expected = s + "a> \"3.103636273531341E3\"" + x + "double> .\n"
                + s + "b> \"1.0E20\"" + x + "double> .\n"
                + s + "c> \"1.5E0\" .\n"
                + s + "d> \"1.0E-5\"" + x + "double> .\n"
                + s + "e> \"123456789012345680\"" + x + "integer> .\n"
                + s + "f> \"1.0E300\"" + x + "double> .\n"
                + s + "g> \"-2.5E0\"" + x + "double> .\n"
                + s + "h> \"100\"" + x + "integer> .\n"
                + s + "i> \"1.0E21\"" + x + "double> .\n";
        assertEquals(expected, new String(Processor.canonicalizeDocumentNativeTypes(doc), StandardCharsets.UTF_8));
    }

    /** Accepted/refused as Go's time.Parse(time.RFC3339, s) does (go1.26). */
    @Test
    void rfc3339MatchesGo() {
        for (String ok : new String[] {"2024-01-01T00:00:00,5Z", "2024-01-01T00:00:00+19:00", "2024-01-01T00:00:00+24:00",
                "2024-01-01T00:00:00-00:60", "2024-01-01T00:00:00.1234567890123Z", "2024-01-01T1:00:00Z",
                "2024-01-01T9:05:07+07:00"}) {
            assertNotNull(Rfc3339.parse(ok), ok);
        }
        for (String bad : new String[] {"2024-01-01T00:00:00+25:00", "2024-01-01T00:00:00+00:61",
                "2024-01-01T24:00:00Z", "2024-1-01T00:00:00Z", "2024-01-1T00:00:00Z", "2024-01-01T00:0:00Z", "2024-01-01T00:00:0Z", "2024-02-30T00:00:00Z", "2024-01-01T00:00:60Z", "2024-01-01t00:00:00Z"}) {
            assertThrows(DateTimeParseException.class, () -> Rfc3339.parse(bad), bad);
        }
        assertEquals(Rfc3339.parse("2024-01-01T00:00:00-00:60"), Rfc3339.parse("2024-01-01T01:00:00Z"));
    }

    @Test
    void schemaPatternsAreLinearTimeAndStackSafe() throws Exception {
        // RE2 matching: these took seconds / overflowed the stack with java.util.regex
        byte[] slow = "{\"type\":\"string\",\"pattern\":\"(.*a){12}x\"}".getBytes(StandardCharsets.UTF_8);
        long t0 = System.nanoTime();
        assertEquals(1, JsonSchemaValidator.validate(slow, "a".repeat(40)).size());
        byte[] deep = "{\"type\":\"string\",\"pattern\":\"^(a|b)*$\"}".getBytes(StandardCharsets.UTF_8);
        assertTrue(JsonSchemaValidator.validate(deep, "ab".repeat(20_000)).isEmpty());
        assertTrue((System.nanoTime() - t0) / 1e9 < 2);
    }

    /** Hashes are Go's DIDDocument.Hash() for the same metadata (json.Unmarshal merges the U+FFFD keys). */
    @Test
    void didDocumentHashMergesLoneSurrogateKeys() throws Exception {
        com.fasterxml.jackson.databind.ObjectMapper om = new com.fasterxml.jackson.databind.ObjectMapper();
        var type = new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {
        };
        com.pila.credential.common.verificationmethod.DIDDocument doc =
                new com.pila.credential.common.verificationmethod.DIDDocument();
        doc.setId("did:example:a");
        doc.setDidDocumentMetadata(om.readValue("{\"\\ud800\":1,\"\\udbff\":2}", type));
        assertEquals("0xeed5f92bc85b0724125edc3b9efdfeffcb97130955bdf0ff9c90d439ba081cfa",
                com.pila.credential.didv2.Documents.hashDIDDocument(doc));
        doc.setDidDocumentMetadata(om.readValue("{\"\\ud800\":2,\"\\udbff\":1}", type));
        assertEquals("0xc425b54b2782f796e8177bd85f1ba01cba143409526c5a460b1424fd19bbf7c0",
                com.pila.credential.didv2.Documents.hashDIDDocument(doc));
    }

    private static String canonJson(String json) throws Exception {
        var om = new com.fasterxml.jackson.databind.ObjectMapper();
        Map<String, Object> ctx = new java.util.LinkedHashMap<>();
        ctx.put("@vocab", "http://ex.org/");
        ctx.put("js", Map.of("@id", "http://ex.org/js", "@type", "@json"));
        Map<String, Object> doc = new java.util.LinkedHashMap<>();
        doc.put("@context", ctx);
        doc.put("@id", "http://ex.org/s");
        doc.put("js", om.readValue(json, Object.class));
        return new String(Processor.canonicalizeDocumentNativeTypes(doc), StandardCharsets.UTF_8);
    }

    /** Titanium wrote at most 7 decimals, so a tampered @json number still hashed the same. */
    @Test
    void jsonLiteralNumbersCannotBeEditedWithoutChangingTheHash() throws Exception {
        String signed = canonJson("{\"maximum\":0.12345678}");
        for (String edited : new String[] {"0.12345679", "0.123456789", "0.1234568", "0.12345677", "0.2"}) {
            assertNotEquals(signed, canonJson("{\"maximum\":" + edited + "}"), edited);
        }
    }

    /** Expected lexical forms are go-credential-sdk's processor.Canonicalize output (json-gold v0.7.0). */
    @Test
    void jsonLiteralsMatchGo() throws Exception {
        String rdfJson = "^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON> .\n";
        String p = "<http://ex.org/s> <http://ex.org/js> \"";
        assertEquals(p + "{\\\"b\\\":[1,1e+21,3103.6362735313405,1e-7,0,100,100000000000000000000,0.5],"
                + "\\\"maximum\\\":0.12345678,\\\"n\\\":null,\\\"s\\\":\\\"x\u00e9\\\\n\\\","
                + "\\\"t\\\":true,\\\"z\\\":{\\\"a\\\":2,\\\"y\\\":1.5}}\"" + rdfJson,
                canonJson("{\"maximum\":0.12345678,\"b\":[1,1e21,3103.6362735313405,1e-7,-0,100,1e20,0.5],"
                        + "\"s\":\"x\u00e9\\n\",\"t\":true,\"n\":null,\"z\":{\"y\":1.5,\"a\":2}}"));
        assertEquals(p + "1.5E0\"" + rdfJson, canonJson("1.5"));
        assertEquals(p + "1.0E21\"" + rdfJson, canonJson("1e21"));
        assertEquals(p + "true\"" + rdfJson, canonJson("true"));
        assertEquals(p + "{}\"" + rdfJson, canonJson("{}"));
        assertEquals(p + "123456789012345680\"" + rdfJson, canonJson("123456789012345678"));
        assertEquals(p + "1.0E-1\"" + rdfJson, canonJson("0.1"));
        assertEquals(p + "JSON Canonicalization error Unexpected EOF reached\"" + rdfJson, canonJson("[]"));
        assertEquals(p + "JSON Canonicalization error Expected '{' but got 's'\"" + rdfJson, canonJson("\"str\""));
    }

    @Test
    void patternsCompileAtSchemaLoad() {
        // Go: "pattern must be a valid regex", even under a property no value reaches
        byte[] bad = "{\"properties\":{\"absent\":{\"pattern\":\"(\"}}}".getBytes(StandardCharsets.UTF_8);
        assertThrows(Exception.class, () -> JsonSchemaValidator.validate(bad, Map.of("other", 1)));
        byte[] badPp = "{\"patternProperties\":{\"(\":{}}}".getBytes(StandardCharsets.UTF_8);
        assertThrows(Exception.class, () -> JsonSchemaValidator.validate(badPp, Map.of()));
        // a data value that merely looks like a keyword is not a pattern
        byte[] ok = "{\"enum\":[{\"pattern\":\"(\"}]}".getBytes(StandardCharsets.UTF_8);
        assertDoesNotThrow(() -> JsonSchemaValidator.validate(ok, Map.of("pattern", "(")));
    }
}
