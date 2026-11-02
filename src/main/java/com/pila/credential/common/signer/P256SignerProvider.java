package com.pila.credential.common.signer;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;

/** Signs with a local P-256 private key (ecdsa-rdfc-2019). */
public final class P256SignerProvider implements SignerProvider {
    private static final ECParameterSpec CURVE_SPEC = ECNamedCurveTable.getParameterSpec("prime256v1");

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final PrivateKey privateKey;

    public P256SignerProvider(String privKeyHex) throws Exception {
        if (privKeyHex == null || privKeyHex.isBlank()) {
            throw new IllegalArgumentException("privKeyHex is required");
        }
        String hex = privKeyHex.startsWith("0x") ? privKeyHex.substring(2) : privKeyHex;
        BigInteger d = new BigInteger(1, Hex.decode(hex));
        if (d.signum() <= 0 || d.compareTo(CURVE_SPEC.getN()) >= 0) {
            throw new IllegalArgumentException("P-256 private key must satisfy 1 <= d < curve order");
        }
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        this.privateKey = kf.generatePrivate(new ECPrivateKeySpec(d, CURVE_SPEC));
    }

    @Override
    public byte[] sign(byte[] digest32) throws Exception {
        if (digest32 == null || digest32.length != 32) {
            throw new IllegalArgumentException("digest must be 32 bytes");
        }
        Signature sig = Signature.getInstance("NONEwithECDSA", "BC");
        sig.initSign(privateKey);
        sig.update(digest32);
        byte[] der = sig.sign();
        return derToRaw64(der);
    }

    private static byte[] derToRaw64(byte[] der) throws Exception {
        org.bouncycastle.asn1.ASN1Sequence seq = (org.bouncycastle.asn1.DLSequence) org.bouncycastle.asn1.ASN1Sequence
                .fromByteArray(der);
        BigInteger r = ((org.bouncycastle.asn1.ASN1Integer) seq.getObjectAt(0)).getPositiveValue();
        BigInteger s = ((org.bouncycastle.asn1.ASN1Integer) seq.getObjectAt(1)).getPositiveValue();
        byte[] out = new byte[64];
        System.arraycopy(toFixed32(r.toByteArray()), 0, out, 0, 32);
        System.arraycopy(toFixed32(s.toByteArray()), 0, out, 32, 32);
        return out;
    }

    private static byte[] toFixed32(byte[] v) {
        if (v.length == 32) {
            return v;
        }
        if (v.length == 33 && v[0] == 0) {
            return Arrays.copyOfRange(v, 1, 33);
        }
        if (v.length > 32) {
            return Arrays.copyOfRange(v, v.length - 32, v.length);
        }
        byte[] out = new byte[32];
        System.arraycopy(v, 0, out, 32 - v.length, v.length);
        return out;
    }
}
