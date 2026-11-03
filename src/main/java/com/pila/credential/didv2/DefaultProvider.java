package com.pila.credential.didv2;

public final class DefaultProvider implements Signer {
    private final byte[] priv32;
    private final String address;

    public DefaultProvider(String privateKeyHex) {
        this.priv32 = Hex.decode(privateKeyHex);
        if (priv32.length != 32) {
            throw new IllegalArgumentException("private key must be 32 bytes");
        }
        this.address = Secp256k1.addressFromPrivate(priv32);
    }

    @Override
    public byte[] sign(byte[] hashPayload) throws Exception {
        byte[] sig = Secp256k1.sign(hashPayload, priv32);
        if (sig.length != 65) {
            throw new Exception("invalid signature length: expected 65 bytes, got " + sig.length);
        }
        return sig;
    }

    @Override
    public String getAddress() {
        return address;
    }
}
