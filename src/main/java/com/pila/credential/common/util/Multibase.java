package com.pila.credential.common.util;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Multibase base58btc ('z') encoding used for ecdsa-rdfc-2019 proofValue.
 */
public final class Multibase {
    private static final char[] ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();
    private static final BigInteger BASE = BigInteger.valueOf(58);
    private static final int[] INDEXES = new int[128];

    static {
        Arrays.fill(INDEXES, -1);
        for (int i = 0; i < ALPHABET.length; i++) {
            INDEXES[ALPHABET[i]] = i;
        }
    }

    private Multibase() {
    }

    public static String encodeBase58Btc(byte[] raw) {
        if (raw == null || raw.length == 0) {
            return "z";
        }
        return "z" + encode(raw);
    }

    public static byte[] decodeBase58Btc(String multibase) {
        if (multibase == null || multibase.isEmpty()) {
            throw new IllegalArgumentException("multibase string is empty");
        }
        if (multibase.charAt(0) != 'z') {
            throw new IllegalArgumentException("expected base58btc multibase prefix 'z'");
        }
        if (multibase.length() == 1) {
            // Go (mr-tron/base58) rejects the empty payload.
            throw new IllegalArgumentException("base58: zero length string");
        }
        return decode(multibase.substring(1));
    }

    private static String encode(byte[] input) {
        int zeros = 0;
        while (zeros < input.length && input[zeros] == 0) {
            zeros++;
        }
        BigInteger value = new BigInteger(1, input);
        StringBuilder sb = new StringBuilder();
        while (value.compareTo(BigInteger.ZERO) > 0) {
            BigInteger[] div = value.divideAndRemainder(BASE);
            sb.insert(0, ALPHABET[div[1].intValue()]);
            value = div[0];
        }
        for (int i = 0; i < zeros; i++) {
            sb.insert(0, '1');
        }
        return sb.toString();
    }

    private static byte[] decode(String input) {
        if (input.isEmpty()) {
            return new byte[0];
        }
        BigInteger value = BigInteger.ZERO;
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 128 || INDEXES[c] == -1) {
                throw new IllegalArgumentException("invalid base58 character");
            }
            value = value.multiply(BASE).add(BigInteger.valueOf(INDEXES[c]));
        }
        byte[] decoded = value.signum() == 0 ? new byte[0] : value.toByteArray();
        int zeros = 0;
        while (zeros < input.length() && input.charAt(zeros) == '1') {
            zeros++;
        }
        if (decoded.length > 1 && decoded[0] == 0) {
            decoded = Arrays.copyOfRange(decoded, 1, decoded.length);
        }
        byte[] withZeros = new byte[zeros + decoded.length];
        System.arraycopy(decoded, 0, withZeros, zeros, decoded.length);
        return withZeros;
    }
}
