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
        assertThrows(Exception.class, () -> JsonSchemaValidator.validate(evil, "a".repeat(40)));
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
}
