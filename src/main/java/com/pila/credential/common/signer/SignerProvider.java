package com.pila.credential.common.signer;

/**
 * SignerProvider signs digests produced by the SDK.
 *
 * <p>
 * Contract:
 * <ul>
 *   <li>{@code digest32} MUST be a 32-byte SHA-256 digest computed by the SDK.</li>
 *   <li>Implementations may return either:</li>
 *   <ul>
 *     <li>64 bytes: {@code R(32) || S(32)}</li>
 *     <li>65 bytes: {@code R(32) || S(32) || V(1)}</li>
 *   </ul>
 * </ul>
 */
public interface SignerProvider {
    /**
     * Signs a 32-byte digest produced by the SDK.
     *
     * <p>
     * The SDK always passes a 32-byte digest; implementations should throw an
     * error if the input is not 32 bytes to avoid accidentally signing raw data.
     */
    byte[] sign(byte[] digest32) throws Exception;
}
