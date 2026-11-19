package com.pila.credential.common.signer;

/**
 * Lets a signer declare its JOSE algorithm for JsonWebSignature2020 (RSA) or a JWS. Signers that do not
 * implement it default to "RS256". The SDK uses it to pick the hash and to write the JWS header
 * (Go signer.AlgorithmProvider).
 */
public interface AlgorithmProvider {
    String algorithm();

    /** Go AlgorithmOf: the provider's JOSE algorithm, "RS256" when it declares none. */
    static String algorithmOf(SignerProvider p) {
        return p instanceof AlgorithmProvider a ? a.algorithm() : "RS256";
    }
}
