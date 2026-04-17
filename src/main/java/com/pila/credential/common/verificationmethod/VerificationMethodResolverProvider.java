package com.pila.credential.common.verificationmethod;

/**
 * Abstraction for resolving verification methods to public keys.
 *
 * Implementations can fetch DID documents from HTTP, chain state, caches, or
 * any other backend without changing verification logic.
 */
public interface VerificationMethodResolverProvider {
    String getPublicKey(String verificationMethodURL) throws Exception;

    String getDefaultPublicKey(String issuer) throws Exception;

    boolean checkVerificationMethod(String privateKey, String verificationMethod) throws Exception;
}
