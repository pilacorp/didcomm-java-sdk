package com.pila.credential.common.schema;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** The table is the output of gojsonschema v1.2.0 for the same inputs (format, quoted value, valid). */
class FormatChecksTest {
    @Test
    void matchesGojsonschema() throws Exception {
        List<String> diffs = new ArrayList<>();
        try (InputStream in = getClass().getResourceAsStream("/gojsonschema-formats.tsv")) {
            for (String line : new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\n")) {
                String[] f = line.split("\t");
                boolean want = Boolean.parseBoolean(f[2]);
                String v = f[1].equals("NUMBER") ? null
                        : f[1].substring(1, f[1].length() - 1).replace("\\\\", "\\").replace("\\\"", "\"");
                if (FormatChecks.isFormat(f[0], v) != want) {
                    diffs.add(f[0] + " " + f[1] + " want " + want);
                }
            }
        }
        assertEquals(List.of(), diffs);
    }

    /** 10,000 inputs (email, uri, uri-reference, uri-template) validated by the real gojsonschema v1.2.0. */
    @Test
    void differentialAgainstGojsonschema() throws Exception {
        var om = new com.fasterxml.jackson.databind.ObjectMapper();
        List<String> diffs = new ArrayList<>();
        int rows = 0;
        try (InputStream in = getClass().getResourceAsStream("/gojsonschema-formats-diff.jsonl")) {
            for (String line : new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\n")) {
                if (line.isBlank()) continue;
                var n = om.readTree(line);
                rows++;
                if (FormatChecks.isFormat(n.get("f").asText(), n.get("v").asText()) != n.get("ok").asBoolean()) {
                    diffs.add(n.get("f").asText() + " " + n.get("v").toString() + " want " + n.get("ok").asBoolean());
                }
            }
        }
        assertEquals(10000, rows);
        assertEquals(List.of(), diffs.subList(0, Math.min(40, diffs.size())), diffs.size() + " differences");
    }
}
