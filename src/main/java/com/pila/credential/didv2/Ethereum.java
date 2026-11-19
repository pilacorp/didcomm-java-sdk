package com.pila.credential.didv2;

import java.nio.charset.StandardCharsets;

public final class Ethereum {
    private Ethereum() {
    }

    public static byte[] personalSignDigest(byte[] message) {
        byte[] prefix = ("\u0019Ethereum Signed Message:\n" + message.length)
                .getBytes(StandardCharsets.UTF_8);
        return Keccak256.hash(prefix, message);
    }

    public static byte[] personalSignDigest(String message) {
        return personalSignDigest(message.getBytes(StandardCharsets.UTF_8));
    }
}
