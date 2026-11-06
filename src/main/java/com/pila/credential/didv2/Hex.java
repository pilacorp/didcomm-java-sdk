package com.pila.credential.didv2;

import java.util.Arrays;

public final class Hex {
    private Hex() {
    }

    public static String normalize(String hex) {
        if (hex == null) {
            return "";
        }
        String s = hex;
        if (s.startsWith("0x") || s.startsWith("0X")) {
            s = s.substring(2);
        }
        return s.toLowerCase();
    }

    public static byte[] decode(String hex) {
        String s = normalize(hex);
        if (s.length() % 2 != 0) {
            throw new IllegalArgumentException("odd hex length");
        }
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = digit(s.charAt(i * 2));
            int lo = digit(s.charAt(i * 2 + 1));
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("invalid hex");
            }
            out[i] = (byte) ((hi << 4) + lo);
        }
        return out;
    }

    /** ASCII hex digit value, -1 otherwise ({@link Character#digit} would accept Unicode digits). */
    static int digit(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    /** Go {@code hex.DecodeString(strings.TrimPrefix(s, "0x"))}: only a lower-case "0x" is dropped. */
    public static byte[] decodeGo(String s) {
        String h = s.startsWith("0x") ? s.substring(2) : s;
        if (h.length() % 2 != 0) {
            throw new IllegalArgumentException("encoding/hex: odd length hex string");
        }
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = digit(h.charAt(i * 2));
            int lo = digit(h.charAt(i * 2 + 1));
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("encoding/hex: invalid byte");
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    public static String encode(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static String encode0x(byte[] bytes) {
        return "0x" + encode(bytes);
    }

    public static byte[] toFixed(byte[] v, int len) {
        if (v.length == len) {
            return Arrays.copyOf(v, len);
        }
        if (v.length > len) {
            return Arrays.copyOfRange(v, v.length - len, v.length);
        }
        byte[] out = new byte[len];
        System.arraycopy(v, 0, out, len - v.length, v.length);
        return out;
    }
}
