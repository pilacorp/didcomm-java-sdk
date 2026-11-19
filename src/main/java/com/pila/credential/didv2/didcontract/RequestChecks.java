package com.pila.credential.didv2.didcontract;

import com.pila.credential.didv2.Issuer;

final class RequestChecks {
    private RequestChecks() {
    }

    static void signature(Issuer.IssuerSignature sig) throws Exception {
        if (sig == null) {
            throw new Exception("issuer signature is required");
        }
        if (sig.v == null || sig.r == null || sig.s == null) {
            throw new Exception("issuer signature V, R, S are required");
        }
    }

    /** 32 bytes as 64 hex chars, an optional lower-case "0x" (Go DocHashHexLength / CapIDHexLength). */
    static void hex32(String name, String v) throws Exception {
        int len = v == null ? 0 : v.length();
        if (v != null && v.startsWith("0x")) {
            len -= 2;
        }
        if (len != 64) {
            throw new Exception("invalid " + name + " length: expected 64 hex chars (32 bytes), got " + len);
        }
    }
}
