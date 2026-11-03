package com.pila.credential.didv2;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * RFC 8785 JSON Canonicalization Scheme, matching go-credential-sdk didv2/did/jsoncanonicalizer.
 */
public final class Rfc8785 {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private Rfc8785() {
    }

    public static byte[] transform(byte[] json) throws Exception {
        JsonNode root = MAPPER.readTree(json);
        StringBuilder sb = new StringBuilder();
        write(root, sb);
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static void write(JsonNode n, StringBuilder sb) throws Exception {
        if (n == null || n.isNull()) {
            sb.append("null");
            return;
        }
        if (n.isBoolean()) {
            sb.append(n.booleanValue() ? "true" : "false");
            return;
        }
        if (n.isNumber()) {
            sb.append(es6(n.doubleValue()));
            return;
        }
        if (n.isTextual()) {
            decorate(n.textValue(), sb);
            return;
        }
        if (n.isArray()) {
            sb.append('[');
            for (int i = 0; i < n.size(); i++) {
                if (i > 0) {
                    sb.append(',');
                }
                write(n.get(i), sb);
            }
            sb.append(']');
            return;
        }
        if (n.isObject()) {
            List<Map.Entry<String, JsonNode>> entries = new ArrayList<>();
            Iterator<Map.Entry<String, JsonNode>> it = n.fields();
            while (it.hasNext()) {
                entries.add(it.next());
            }
            entries.sort((a, b) -> utf16Compare(a.getKey(), b.getKey()));
            sb.append('{');
            for (int i = 0; i < entries.size(); i++) {
                if (i > 0) {
                    sb.append(',');
                }
                decorate(entries.get(i).getKey(), sb);
                sb.append(':');
                write(entries.get(i).getValue(), sb);
            }
            sb.append('}');
            return;
        }
        throw new Exception("unsupported JSON node");
    }

    private static int utf16Compare(String a, String b) {
        int n = Math.min(a.length(), b.length());
        for (int i = 0; i < n; i++) {
            int d = Character.codePointAt(a, i) - Character.codePointAt(b, i);
            // UTF-16 code units: compare char values
            d = a.charAt(i) - b.charAt(i);
            if (d != 0) {
                return d;
            }
        }
        return a.length() - b.length();
    }

    private static void decorate(String raw, StringBuilder sb) {
        sb.append('"');
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '"' -> sb.append("\\\"");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }

    private static String es6(double ieeeF64) throws Exception {
        long bits = Double.doubleToRawLongBits(ieeeF64);
        if ((bits & 0x7ff0000000000000L) == 0x7ff0000000000000L) {
            throw new Exception("Invalid JSON number");
        }
        if (ieeeF64 == 0) {
            return "0";
        }
        String sign = "";
        if (ieeeF64 < 0) {
            ieeeF64 = -ieeeF64;
            sign = "-";
        }
        String formatted;
        if (ieeeF64 < 1e21 && ieeeF64 >= 1e-6) {
            formatted = stripTrailing(Double.toString(ieeeF64));
        } else {
            formatted = String.format(java.util.Locale.US, "%e", ieeeF64);
            formatted = formatted.replace("e+", "e+").replace("e-", "e-");
            int exp = formatted.indexOf('e');
            if (exp > 0 && formatted.length() > exp + 2 && formatted.charAt(exp + 2) == '0') {
                formatted = formatted.substring(0, exp + 2) + formatted.substring(exp + 3);
            }
        }
        return sign + formatted;
    }

    private static String stripTrailing(String s) {
        if (s.contains("E") || s.contains("e")) {
            return s.replace('E', 'e');
        }
        if (s.indexOf('.') < 0) {
            return s;
        }
        int i = s.length() - 1;
        while (i > 0 && s.charAt(i) == '0') {
            i--;
        }
        if (s.charAt(i) == '.') {
            i--;
        }
        return s.substring(0, i + 1);
    }
}
