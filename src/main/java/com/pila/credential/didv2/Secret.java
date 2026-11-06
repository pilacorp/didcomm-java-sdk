package com.pila.credential.didv2;

/** The generated DID private key returned by {@code generateDID} (Go didv2.Secret). */
public final class Secret {
    public final String privateKeyHex;

    public Secret(String privateKeyHex) {
        this.privateKeyHex = privateKeyHex;
    }
}
