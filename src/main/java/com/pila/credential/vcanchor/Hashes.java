package com.pila.credential.vcanchor;

import java.util.Locale;

final class Hashes {
    private Hashes() {
    }

    /** Go normalizeHash32: trim, lowercase, strip 0x, exactly 32 bytes of hex; returns "0x"+hex. */
    static String normalize32(String value) {
        String s = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        if (s.startsWith("0x")) {
            s = s.substring(2);
        }
        if (s.length() % 2 != 0 || !s.chars().allMatch(c -> Character.digit(c, 16) >= 0 && c < 128)) {
            throw new IllegalArgumentException("invalid 32-byte hash \"" + value + "\": invalid hex");
        }
        if (s.length() != 64) {
            throw new IllegalArgumentException(
                    "invalid 32-byte hash \"" + value + "\": got " + s.length() / 2 + " bytes");
        }
        return "0x" + s;
    }

    static byte[] raw(String normalized) {
        return com.pila.credential.didv2.Hex.decode(normalized);
    }

    static String hex(byte[] raw) {
        return com.pila.credential.didv2.Hex.encode0x(raw);
    }
}
