package com.pila.credential.didv2;

import java.io.ByteArrayOutputStream;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * RFC 8785 JSON Canonicalization Scheme: a port of go-credential-sdk's
 * {@code didv2/did/jsoncanonicalizer} (the WebPKI.org reference), so the same inputs are accepted and
 * rejected: the top level must be an object or array, duplicate keys and a lone surrogate escape are
 * errors, numbers go through float64 and the ES6 formatter.
 */
public final class Rfc8785 {
    // ponytail: Go's ParseFloat also takes hex floats ("0x1p-2"); those are rejected here.
    private static final Pattern NUMBER = Pattern.compile("[+-]?(\\d+\\.?\\d*|\\.\\d+)([eE][+-]?\\d+)?");
    private static final byte[] ASCII_ESCAPES = {'\\', '"', 'b', 'f', 'n', 'r', 't'};
    private static final byte[] BINARY_ESCAPES = {'\\', '"', '\b', '\f', '\n', '\r', '\t'};

    private final byte[] d;
    private int i;

    private Rfc8785(byte[] data) {
        this.d = data;
    }

    public static byte[] transform(byte[] json) throws Exception {
        return new Rfc8785(json).run();
    }

    private byte[] run() throws Exception {
        byte[] out;
        if (peek() == '[') {
            scan();
            out = parseArray();
        } else {
            scanFor('{');
            out = parseObject();
        }
        while (i < d.length) {
            if (!isWhiteSpace(d[i] & 0xff)) {
                throw new Exception("Improperly terminated JSON object");
            }
            i++;
        }
        return out;
    }

    private static boolean isWhiteSpace(int c) {
        return c == 0x20 || c == 0x0a || c == 0x0d || c == 0x09;
    }

    private int nextChar() throws Exception {
        if (i >= d.length) {
            throw new Exception("Unexpected EOF reached");
        }
        int c = d[i++] & 0xff;
        if (c > 0x7f) {
            throw new Exception("Unexpected non-ASCII character");
        }
        return c;
    }

    private int scan() throws Exception {
        while (true) {
            int c = nextChar();
            if (!isWhiteSpace(c)) {
                return c;
            }
        }
    }

    private void scanFor(char expected) throws Exception {
        int c = scan();
        if (c != expected) {
            throw new Exception("Expected '" + expected + "' but got '" + (char) c + "'");
        }
    }

    private int peek() throws Exception {
        int save = i;
        int c = scan();
        i = save;
        return c;
    }

    private int uEscape() throws Exception {
        int start = i;
        for (int k = 0; k < 4; k++) {
            nextChar();
        }
        String hex = new String(d, start, 4, StandardCharsets.US_ASCII);
        try {
            return Integer.parseUnsignedInt(hex, 16);
        } catch (NumberFormatException e) {
            throw new Exception("invalid \\u escape: " + hex);
        }
    }

    private byte[] parseElement() throws Exception {
        return switch (scan()) {
            case '{' -> parseObject();
            case '"' -> decorate(parseQuotedString());
            case '[' -> parseArray();
            default -> parseSimpleType();
        };
    }

    private byte[] parseQuotedString() throws Exception {
        ByteArrayOutputStream raw = new ByteArrayOutputStream();
        while (true) {
            if (i >= d.length) {
                nextChar(); // EOF error
            }
            int c = d[i++] & 0xff;
            if (c == '"') {
                break;
            }
            if (c < ' ') {
                throw new Exception("Unterminated string literal");
            } else if (c == '\\') {
                c = nextChar();
                if (c == 'u') {
                    int first = uEscape();
                    if (first >= 0xD800 && first <= 0xDFFF) {
                        if (nextChar() != '\\' || nextChar() != 'u') {
                            throw new Exception("Missing surrogate");
                        }
                        int second = uEscape();
                        if (first <= 0xDBFF && second >= 0xDC00 && second <= 0xDFFF) {
                            writeRune(raw, Character.toCodePoint((char) first, (char) second));
                        } else {
                            writeRune(raw, 0xFFFD);
                        }
                    } else {
                        writeRune(raw, first);
                    }
                } else if (c == '/') {
                    raw.write('/');
                } else {
                    int k = indexOf(ASCII_ESCAPES, c);
                    if (k < 0) {
                        throw new Exception("Unexpected escape: \\" + (char) c);
                    }
                    raw.write(BINARY_ESCAPES[k]);
                }
            } else {
                raw.write(c);
            }
        }
        return raw.toByteArray();
    }

    private static void writeRune(ByteArrayOutputStream out, int cp) {
        out.writeBytes(new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8));
    }

    private static int indexOf(byte[] arr, int c) {
        for (int k = 0; k < arr.length; k++) {
            if (arr[k] == c) {
                return k;
            }
        }
        return -1;
    }

    private static byte[] decorate(byte[] raw) {
        ByteArrayOutputStream q = new ByteArrayOutputStream(raw.length + 2);
        q.write('"');
        for (byte b : raw) {
            int c = b & 0xff;
            int k = indexOf(BINARY_ESCAPES, c);
            if (k >= 0) {
                q.write('\\');
                q.write(ASCII_ESCAPES[k]);
            } else if (c < 0x20) {
                q.writeBytes(String.format("\\u%04x", c).getBytes(StandardCharsets.US_ASCII));
            } else {
                q.write(c);
            }
        }
        q.write('"');
        return q.toByteArray();
    }

    private byte[] parseSimpleType() throws Exception {
        i--;
        StringBuilder token = new StringBuilder();
        while (true) {
            int c = peek();
            if (c == ',' || c == ']' || c == '}') {
                break;
            }
            c = nextChar();
            if (isWhiteSpace(c)) {
                break;
            }
            token.append((char) c);
        }
        if (token.length() == 0) {
            throw new Exception("Missing argument");
        }
        String value = token.toString();
        if (value.equals("true") || value.equals("false") || value.equals("null")) {
            return value.getBytes(StandardCharsets.US_ASCII);
        }
        if (!NUMBER.matcher(value).matches()) {
            throw new Exception("invalid JSON value: " + value);
        }
        return numberToJson(Double.parseDouble(value)).getBytes(StandardCharsets.US_ASCII);
    }

    private byte[] parseArray() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write('[');
        boolean next = false;
        while (peek() != ']') {
            if (next) {
                scanFor(',');
                out.write(',');
            } else {
                next = true;
            }
            out.writeBytes(parseElement());
        }
        scan();
        out.write(']');
        return out.toByteArray();
    }

    private record Member(byte[] name, String sortKey, byte[] value) {
    }

    private byte[] parseObject() throws Exception {
        List<Member> members = new ArrayList<>();
        boolean next = false;
        while (peek() != '}') {
            if (next) {
                scanFor(',');
            }
            next = true;
            scanFor('"');
            byte[] name = parseQuotedString();
            // Sorted on UTF-16 code units; invalid UTF-8 decodes to U+FFFD exactly as Go's []rune conversion.
            String sortKey = new String(name, StandardCharsets.UTF_8);
            scanFor(':');
            Member m = new Member(name, sortKey, parseElement());
            int at = members.size();
            for (int k = 0; k < members.size(); k++) {
                int cmp = sortKey.compareTo(members.get(k).sortKey());
                if (cmp == 0) {
                    throw new Exception("Duplicate key: " + new String(members.get(k).name(), StandardCharsets.UTF_8));
                }
                if (cmp < 0) {
                    at = k;
                    break;
                }
            }
            members.add(at, m);
        }
        scan();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write('{');
        for (int k = 0; k < members.size(); k++) {
            if (k > 0) {
                out.write(',');
            }
            out.writeBytes(decorate(members.get(k).name()));
            out.write(':');
            out.writeBytes(members.get(k).value());
        }
        out.write('}');
        return out.toByteArray();
    }

    /** ES6 Number-to-string, as Go's {@code NumberToJSON}: shortest digits, 'f' form in [1e-6, 1e21). */
    static String numberToJson(double v) throws Exception {
        if (Double.isNaN(v) || Double.isInfinite(v)) {
            throw new Exception("Invalid JSON number: " + Long.toHexString(Double.doubleToRawLongBits(v)));
        }
        if (v == 0) {
            return "0";
        }
        String sign = v < 0 ? "-" : "";
        double a = Math.abs(v);
        BigDecimal bd = com.pila.credential.common.processor.Processor.shortestDecimal(a);
        String digits = bd.unscaledValue().toString();
        int nd = digits.length();
        int dp = nd - bd.scale();
        if (a < 1e21 && a >= 1e-6) {
            if (dp <= 0) {
                return sign + "0." + "0".repeat(-dp) + digits;
            }
            if (dp >= nd) {
                return sign + digits + "0".repeat(dp - nd);
            }
            return sign + digits.substring(0, dp) + "." + digits.substring(dp);
        }
        int exp = dp - 1;
        String mant = nd == 1 ? digits : digits.charAt(0) + "." + digits.substring(1);
        return sign + mant + "e" + (exp < 0 ? "-" : "+") + Math.abs(exp);
    }
}
