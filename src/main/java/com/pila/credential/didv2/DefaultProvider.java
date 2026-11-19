package com.pila.credential.didv2;

public final class DefaultProvider implements Signer {
    private final byte[] priv32;
    private final String address;

    public DefaultProvider(String privateKeyHex) {
        this.priv32 = Hex.decodeGo(privateKeyHex);
        if (priv32.length != 32) {
            throw new IllegalArgumentException("private key must be 32 bytes");
        }
        java.math.BigInteger d = new java.math.BigInteger(1, priv32);
        if (d.signum() == 0 || d.compareTo(Secp256k1.N) >= 0) {
            throw new IllegalArgumentException("invalid private key: scalar must be in [1, n-1]");
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
