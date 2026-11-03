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
            int hi = Character.digit(s.charAt(i * 2), 16);
            int lo = Character.digit(s.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("invalid hex");
            }
            out[i] = (byte) ((hi << 4) + lo);
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
