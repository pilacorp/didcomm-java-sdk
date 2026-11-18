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
}
