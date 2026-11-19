package com.pila.credential.common.verificationmethod;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.Iterator;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** 4.22: accepts exactly what Go's time.Parse(time.RFC3339) accepts (go-fixtures/go-facts.json). */
class Rfc3339StrictTest {

    @Test
    void matchesGoTimeParse() throws Exception {
        JsonNode facts;
        try (InputStream in = getClass().getResourceAsStream("/go-fixtures/go-facts.json")) {
            facts = new ObjectMapper().readTree(in);
        }
        Iterator<Map.Entry<String, JsonNode>> it = facts.get("rfc3339").fields();
        while (it.hasNext()) {
            Map.Entry<String, JsonNode> e = it.next();
            boolean ok;
            try {
                StrictPurposeCheck.parseRfc3339(e.getKey(), "created");
                ok = true;
            } catch (Exception ex) {
                ok = false;
            }
            assertEquals(e.getValue().asBoolean(), ok, "'" + e.getKey() + "'");
        }
    }
}
