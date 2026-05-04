package com.pila.credential.common.signer;

public final class TestSignerProvider implements SignerProvider {
    private final byte[] signature;

    public TestSignerProvider(byte[] signature) {
        this.signature = signature;
    }

    @Override
    public byte[] sign(byte[] digest32) throws Exception {
        return signature;
    }
}

