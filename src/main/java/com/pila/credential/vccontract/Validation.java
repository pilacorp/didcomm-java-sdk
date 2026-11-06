package com.pila.credential.vccontract;

import java.util.Locale;

/** Hex/address checks shared by the request models and the registry (Go model.go + hexToBytes32). */
final class Validation {
    private Validation() {
    }

    /** Go common.IsHexAddress: 40 hex chars, optional 0x/0X prefix. */
    static boolean isHexAddress(String s) {
        if (s == null) {
            return false;
        }
        String h = s.startsWith("0x") || s.startsWith("0X") ? s.substring(2) : s;
        return h.length() == 40 && isHex(h);
    }

    static boolean isHex(String h) {
        for (int i = 0; i < h.length(); i++) {
            char c = h.charAt(i);
            if (!(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F')) {
                return false;
            }
        }
        return true;
    }

    /** "0x"-prefixed lowercase form of a validated address. */
    static String address(String s) {
        return "0x" + (s.startsWith("0x") || s.startsWith("0X") ? s.substring(2) : s).toLowerCase(Locale.ROOT);
    }

    /** Go validateHash32: length only (hex content is checked later, when decoding). Lowercase 0x only. */
    static void validateHash32(String s) {
        String t = s != null && s.startsWith("0x") ? s.substring(2) : (s == null ? "" : s);
        if (t.length() != 64) {
            throw new IllegalArgumentException("expected 64 hex chars (32 bytes), got " + t.length());
        }
    }

    static void validateProofFields(String issuerAddress, String leaf, java.util.List<String> proof) {
        if (!isHexAddress(issuerAddress)) {
            throw new IllegalArgumentException("invalid issuer address: \"" + issuerAddress + "\"");
        }
        try {
            validateHash32(leaf);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("invalid leaf: " + e.getMessage());
        }
        if (proof != null) {
            for (int i = 0; i < proof.size(); i++) {
                try {
                    validateHash32(proof.get(i));
                } catch (IllegalArgumentException e) {
                    throw new IllegalArgumentException("invalid proof element at index " + i + ": " + e.getMessage());
                }
            }
        }
    }
}
