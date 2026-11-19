package com.pila.credential.common.signer;

/** A callback signer (HSM / KMS / remote signing): receives the digest, returns the raw signature. */
@FunctionalInterface
public interface SignerFunction {
    byte[] sign(byte[] digest) throws Exception;
}
