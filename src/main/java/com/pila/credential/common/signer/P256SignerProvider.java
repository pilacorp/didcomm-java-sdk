package com.pila.credential.common.signer;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.util.Arrays;

/**
 * Signs a 32-byte digest with a P-256 key (ecdsa-rdfc-2019, ecdsa-sd-2023, JOSE ES256), producing a 64-byte
 * R||S signature with a low S. Backed by an in-memory key ({@link #P256SignerProvider(String)},
 * {@link #P256SignerProvider(PrivateKey)}) or by a callback ({@link #fromFunc}) for an HSM/KMS (Go
 * NewP256Provider / NewP256ProviderFromHex / NewP256Func).
 */
public final class P256SignerProvider implements SignerProvider, AlgorithmProvider {
    private static final ECParameterSpec CURVE_SPEC = ECNamedCurveTable.getParameterSpec("prime256v1");

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final SignerFunction signFn;
    private final PublicKey publicKey;

    /** Hex scalar (32-byte private exponent, "0x" optional; a hex omitting leading zero bytes is left-padded). */
    public P256SignerProvider(String privKeyHex) throws Exception {
        this(keyFromScalar(privKeyHex));
    }

    /** In-memory key; must be a P-256 EC private key. */
    public P256SignerProvider(PrivateKey priv) throws Exception {
        if (priv == null) {
            throw new IllegalArgumentException("p256 private key is nil");
        }
        if (!(priv instanceof ECPrivateKey ec) || !CURVE_SPEC.getN().equals(ec.getParams().getOrder())) {
            throw new IllegalArgumentException("private key is not P-256");
        }
        BigInteger d = ec.getS();
        org.bouncycastle.math.ec.ECPoint q = CURVE_SPEC.getG().multiply(d).normalize();
        this.publicKey = KeyFactory.getInstance("EC", "BC")
                .generatePublic(new org.bouncycastle.jce.spec.ECPublicKeySpec(q, CURVE_SPEC));
        PrivateKey bcPriv = KeyFactory.getInstance("EC", "BC").generatePrivate(new ECPrivateKeySpec(d, CURVE_SPEC));
        this.signFn = digest -> {
            Signature sig = Signature.getInstance("NONEwithECDSA", "BC");
            sig.initSign(bcPriv);
            sig.update(digest);
            return derToRaw64(sig.sign());
        };
    }

    private P256SignerProvider(SignerFunction fn) {
        this.signFn = fn;
        this.publicKey = null;
    }

    /**
     * A P-256 signer that delegates to {@code signFn}, which receives the 32-byte digest and must return a 64-byte
     * R||S signature (Go NewP256Func). {@link #getPublic()} is null.
     */
    public static P256SignerProvider fromFunc(SignerFunction signFn) {
        if (signFn == null) {
            throw new IllegalArgumentException("sign function is nil");
        }
        return new P256SignerProvider(signFn);
    }

    private static PrivateKey keyFromScalar(String privKeyHex) throws Exception {
        if (privKeyHex == null || privKeyHex.isBlank()) {
            throw new IllegalArgumentException("privKeyHex is required");
        }
        String hex = privKeyHex.startsWith("0x") ? privKeyHex.substring(2) : privKeyHex;
        BigInteger d = new BigInteger(1, Hex.decode(hex));
        if (d.signum() <= 0 || d.compareTo(CURVE_SPEC.getN()) >= 0) {
            throw new IllegalArgumentException("P-256 private key must satisfy 1 <= d < curve order");
        }
        return KeyFactory.getInstance("EC", "BC").generatePrivate(new ECPrivateKeySpec(d, CURVE_SPEC));
    }

    /** The P-256 public key, or null for a callback-based provider. */
    public PublicKey getPublic() {
        return publicKey;
    }

    /** JOSE algorithm for P-256 JsonWebSignature2020 / JOSE (ES256). */
    @Override
    public String algorithm() {
        return "ES256";
    }

    @Override
    public byte[] sign(byte[] digest32) throws Exception {
        if (digest32 == null || digest32.length != 32) {
            throw new IllegalArgumentException("digest must be 32 bytes");
        }
        return signFn.sign(digest32);
    }

    private static byte[] derToRaw64(byte[] der) throws Exception {
        org.bouncycastle.asn1.ASN1Sequence seq = (org.bouncycastle.asn1.ASN1Sequence) org.bouncycastle.asn1.ASN1Sequence
                .fromByteArray(der);
        BigInteger r = ((org.bouncycastle.asn1.ASN1Integer) seq.getObjectAt(0)).getPositiveValue();
        BigInteger s = LowS.normalize(CURVE_SPEC.getN(),
                ((org.bouncycastle.asn1.ASN1Integer) seq.getObjectAt(1)).getPositiveValue());
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
