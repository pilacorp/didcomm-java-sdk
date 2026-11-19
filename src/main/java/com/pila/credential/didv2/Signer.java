package com.pila.credential.didv2;

public interface Signer {
    byte[] sign(byte[] digest32) throws Exception;

    String getAddress();
}
