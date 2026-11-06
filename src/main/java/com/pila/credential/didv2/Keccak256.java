package com.pila.credential.didv2;

import org.bouncycastle.crypto.digests.KeccakDigest;

public final class Keccak256 {
    private Keccak256() {
    }

    public static byte[] hash(byte[]... parts) {
        KeccakDigest d = new KeccakDigest(256);
        for (byte[] p : parts) {
            if (p != null && p.length > 0) {
                d.update(p, 0, p.length);
            }
        }
        byte[] out = new byte[32];
        d.doFinal(out, 0);
        return out;
    }

    public static String hashHex(byte[]... parts) {
        return Hex.encode0x(hash(parts)).toLowerCase();
    }
}
