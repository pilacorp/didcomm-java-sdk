package com.pila.credential.common.signer;

public interface SignerProvider {
    /**
     * Signs a 32-byte SHA-256 digest produced by the SDK.
     * Implementations may return 64 bytes (R||S) or 65 bytes (R||S||V).
     */
    byte[] sign(byte[] digest32) throws Exception;
}
