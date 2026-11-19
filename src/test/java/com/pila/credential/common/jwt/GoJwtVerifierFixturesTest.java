package com.pila.credential.common.jwt;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.verificationmethod.DIDDocument;
import com.pila.credential.common.verificationmethod.StaticDocumentResolver;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** JWTs signed by Go's own code, each with the verdict of Go's JWTVerifier.VerifyJWT. */
class GoJwtVerifierFixturesTest {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    @TestFactory
    List<DynamicTest> javaAgreesWithGo() throws Exception {
        JsonNode root;
        try (InputStream in = getClass().getResourceAsStream("/go-fixtures/jwt-verifier.json")) {
            root = MAPPER.readTree(in);
        }
        DIDDocument doc = MAPPER.treeToValue(root.get("didDocument"), DIDDocument.class);
        JWTVerifier verifier = new JWTVerifier(new StaticDocumentResolver(doc));
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode c : root.get("cases")) {
            String name = c.get("name").asText();
            boolean goVerified = c.get("goVerified").asBoolean();
            tests.add(DynamicTest.dynamicTest(name, () -> {
                boolean ok;
                try {
                    verifier.verifyJWT(c.get("token").asText());
                    ok = true;
                } catch (Exception e) {
                    ok = false;
                }
                assertEquals(goVerified, ok, name);
            }));
        }
        return tests;
    }

    @Test
    void equalFoldMatchesGoNotJavaIgnoreCase() {
        assertTrue(JWTVerifier.equalFold("issuer", "Issuer"));
        assertTrue(JWTVerifier.equalFold("issuer", "iſſuer")); // long s folds to s
        assertTrue(JWTVerifier.equalFold("k", "K")); // Kelvin sign folds to k
        assertFalse(JWTVerifier.equalFold("issuer", "ıssuer")); // dotless i does not fold to i in Go
        assertFalse(JWTVerifier.equalFold("issuer", "İssuer"));
        assertTrue("ı".equalsIgnoreCase("I")); // what Java would have rejected
    }
}
