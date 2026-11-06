package com.pila.credential.common.verificationmethod;

public interface DocumentResolver {
    DIDDocument resolveDocument(String did) throws Exception;
}
