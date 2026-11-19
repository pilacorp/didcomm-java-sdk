package com.pila.credential.common.verificationmethod;

import com.pila.credential.common.util.Multibase;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.util.Arrays;

/**
 * W3C Multikey (publicKeyMultibase) encoding, Go parity with key_material.go.
 * p256-pub multicodec 0x1200 is varint 0x80 0x24, p384-pub 0x1201 is 0x81 0x24,
 * p256-priv 0x1306 is 0x86 0x26.
 */
public final class Multikey {
    static final byte[] P256_PUB_MULTICODEC = new byte[] { (byte) 0x80, 0x24 };
    static final byte[] P384_PUB_MULTICODEC = new byte[] { (byte) 0x81, 0x24 };
    static final byte[] P256_PRIV_MULTICODEC = new byte[] { (byte) 0x86, 0x26 };

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private Multikey() {
    }

    /** Curves a Multikey may name (CID 1.0 ECDSA curves). */
    public enum Curve {
        P256("P-256", "prime256v1", 32),
        P384("P-384", "secp384r1", 48);

        public final String jwkName;
        final String jcaName;
        public final int size;

        Curve(String jwkName, String jcaName, int size) {
            this.jwkName = jwkName;
            this.jcaName = jcaName;
            this.size = size;
        }

        X9ECParameters params() {
            return CustomNamedCurves.getByName(jwkName);
        }
    }

    /** Decoded EC Multikey: the curve (from the prefix) and the on-curve point. */
    public record EcKey(Curve curve, ECPoint point) {
        public PublicKey toPublicKey() throws Exception {
            KeyFactory kf = KeyFactory.getInstance("EC", "BC");
            return kf.generatePublic(new org.bouncycastle.jce.spec.ECPublicKeySpec(point,
                    ECNamedCurveTable.getParameterSpec(curve.jcaName)));
        }
    }

    public static boolean isP256PublicMultibase(String multibase) {
        try {
            return decodeEc(multibase).curve() == Curve.P256;
        } catch (Exception e) {
            return false;
        }
    }

    /** Raw bytes of a base58btc ('z') multibase string, including the multicodec prefix. */
    public static byte[] decodeMultibaseKey(String s) throws Exception {
        if (s == null || s.isEmpty() || s.charAt(0) != 'z') {
            throw new Exception("multikey: expected base58btc 'z' multibase");
        }
        try {
            return Multibase.decodeBase58Btc(s);
        } catch (IllegalArgumentException e) {
            throw new Exception("multikey: base58 decode: " + e.getMessage(), e);
        }
    }

    public static String encodeMultibaseKey(byte[] raw) {
        return Multibase.encodeBase58Btc(raw);
    }

    /** Go ECPubFromMultikeyBytes: curve from the prefix, exactly one compressed point (02/03). */
    public static EcKey decodeEcBytes(byte[] raw) throws Exception {
        if (raw == null || raw.length < 2) {
            throw new Exception("multikey: value too short");
        }
        Curve curve;
        if (raw[0] == P256_PUB_MULTICODEC[0] && raw[1] == P256_PUB_MULTICODEC[1]) {
            curve = Curve.P256;
        } else if (raw[0] == P384_PUB_MULTICODEC[0] && raw[1] == P384_PUB_MULTICODEC[1]) {
            curve = Curve.P384;
        } else {
            throw new Exception(String.format("multikey: unsupported multicodec prefix 0x%02x%02x", raw[0], raw[1]));
        }
        byte[] compressed = Arrays.copyOfRange(raw, 2, raw.length);
        if (compressed.length != 1 + curve.size || (compressed[0] != 0x02 && compressed[0] != 0x03)) {
            throw new Exception("multikey: invalid " + curve.jwkName + " compressed point");
        }
        ECPoint point;
        try {
            point = curve.params().getCurve().decodePoint(compressed);
        } catch (Exception e) {
            throw new Exception("multikey: invalid " + curve.jwkName + " compressed point", e);
        }
        if (point == null || point.isInfinity() || !point.isValid()) {
            throw new Exception("multikey: invalid " + curve.jwkName + " compressed point");
        }
        return new EcKey(curve, point.normalize());
    }

    public static EcKey decodeEc(String multibase) throws Exception {
        return decodeEcBytes(decodeMultibaseKey(multibase));
    }

    public static VerificationMethodKeyKind kindFromMultibase(String multibase) throws Exception {
        Curve c = decodeEc(multibase).curve();
        if (c == Curve.P256) {
            return VerificationMethodKeyKind.P256;
        }
        throw new Exception("multikey: unsupported curve " + c.jwkName + " for a signing key kind");
    }

    /** P-256 only (kept for the data-integrity paths); P-384 keys are rejected here. */
    public static PublicKey publicKeyFromMultibase(String multibase) throws Exception {
        EcKey k = decodeEc(multibase);
        if (k.curve() != Curve.P256) {
            throw new Exception("multikey: not a p256-pub multikey");
        }
        return k.toPublicKey();
    }

    public static String encodeP256PublicXY(byte[] uncompressed64) throws Exception {
        if (uncompressed64 == null || uncompressed64.length != 64) {
            throw new Exception("multikey: NewP256MultikeyVM requires a P-256 public key");
        }
        byte[] encoded = new byte[65];
        encoded[0] = 0x04;
        System.arraycopy(uncompressed64, 0, encoded, 1, 64);
        return encodePoint(Curve.P256, encoded);
    }

    public static String encodeP256PublicKey(PublicKey publicKey) throws Exception {
        return encodePublicKey(publicKey, Curve.P256);
    }

    /** Go EncodePubMultibase: P-256 or P-384, curve checked, point must be on the curve. */
    public static String encodePublicKey(PublicKey publicKey) throws Exception {
        if (!(publicKey instanceof java.security.interfaces.ECPublicKey ec)) {
            throw new Exception("multikey: expected EC public key");
        }
        for (Curve c : Curve.values()) {
            if (c.params().getN().equals(ec.getParams().getOrder())) {
                return encodePublicKey(publicKey, c);
            }
        }
        throw new Exception("multikey: unsupported curve");
    }

    private static String encodePublicKey(PublicKey publicKey, Curve curve) throws Exception {
        if (!(publicKey instanceof java.security.interfaces.ECPublicKey ec)) {
            throw new Exception("multikey: expected EC public key");
        }
        if (!curve.params().getN().equals(ec.getParams().getOrder())) {
            throw new Exception("multikey: key is not on " + curve.jwkName);
        }
        byte[] sec1 = new byte[1 + 2 * curve.size];
        sec1[0] = 0x04;
        byte[] x = fixedBytes(ec.getW().getAffineX(), curve.size);
        byte[] y = fixedBytes(ec.getW().getAffineY(), curve.size);
        System.arraycopy(x, 0, sec1, 1, curve.size);
        System.arraycopy(y, 0, sec1, 1 + curve.size, curve.size);
        return encodePoint(curve, sec1);
    }

    private static byte[] fixedBytes(BigInteger v, int len) {
        byte[] b = v.toByteArray();
        byte[] out = new byte[len];
        if (b.length > len) {
            System.arraycopy(b, b.length - len, out, 0, len);
        } else {
            System.arraycopy(b, 0, out, len - b.length, b.length);
        }
        return out;
    }

    private static String encodePoint(Curve curve, byte[] sec1) throws Exception {
        ECPoint point;
        try {
            point = curve.params().getCurve().decodePoint(sec1);
        } catch (Exception e) {
            throw new Exception("multikey: point is not on " + curve.jwkName, e);
        }
        if (point.isInfinity() || !point.isValid()) {
            throw new Exception("multikey: point is not on " + curve.jwkName);
        }
        byte[] prefix = curve == Curve.P256 ? P256_PUB_MULTICODEC : P384_PUB_MULTICODEC;
        byte[] compressed = point.getEncoded(true);
        byte[] raw = new byte[prefix.length + compressed.length];
        System.arraycopy(prefix, 0, raw, 0, prefix.length);
        System.arraycopy(compressed, 0, raw, prefix.length, compressed.length);
        return Multibase.encodeBase58Btc(raw);
    }

    /** Go DecodeP256PrivMultibase: exactly 32 bytes, scalar in [1, n-1]. */
    public static BigInteger decodeP256PrivMultibase(String s) throws Exception {
        byte[] raw = decodeMultibaseKey(s);
        if (raw.length < 2 || raw[0] != P256_PRIV_MULTICODEC[0] || raw[1] != P256_PRIV_MULTICODEC[1]) {
            throw new Exception("multikey: not a p256-priv multikey");
        }
        byte[] d = Arrays.copyOfRange(raw, 2, raw.length);
        if (d.length != 32) {
            throw new Exception("multikey: p256 secret key must be 32 bytes, got " + d.length);
        }
        BigInteger scalar = new BigInteger(1, d);
        if (scalar.signum() == 0 || scalar.compareTo(Curve.P256.params().getN()) >= 0) {
            throw new Exception("multikey: invalid p256 secret key");
        }
        return scalar;
    }
}
