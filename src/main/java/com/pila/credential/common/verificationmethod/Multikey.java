package com.pila.credential.common.verificationmethod;

import com.pila.credential.common.util.Multibase;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.util.Arrays;

/**
 * W3C Multikey (publicKeyMultibase) encoding used by go-credential-sdk DID v2 P-256 keys.
 * p256-pub multicodec 0x1200 is varint-encoded as 0x80 0x24.
 */
public final class Multikey {
    static final byte[] P256_PUB_MULTICODEC = new byte[] { (byte) 0x80, 0x24 };

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private Multikey() {
    }

    public static boolean isP256PublicMultibase(String multibase) {
        try {
            return publicKeyFromMultibase(multibase) != null && kindFromMultibase(multibase) == VerificationMethodKeyKind.P256;
        } catch (Exception e) {
            return false;
        }
    }

    public static VerificationMethodKeyKind kindFromMultibase(String multibase) throws Exception {
        byte[] raw = Multibase.decodeBase58Btc(multibase);
        if (raw.length < 3) {
            throw new Exception("multikey: value too short");
        }
        if (raw[0] == P256_PUB_MULTICODEC[0] && raw[1] == P256_PUB_MULTICODEC[1]) {
            return VerificationMethodKeyKind.P256;
        }
        throw new Exception(String.format("multikey: unsupported multicodec prefix 0x%02x%02x", raw[0], raw[1]));
    }

    public static PublicKey publicKeyFromMultibase(String multibase) throws Exception {
        byte[] raw = Multibase.decodeBase58Btc(multibase);
        if (raw.length < 3) {
            throw new Exception("multikey: value too short");
        }
        if (raw[0] != P256_PUB_MULTICODEC[0] || raw[1] != P256_PUB_MULTICODEC[1]) {
            throw new Exception("multikey: not a p256-pub multikey");
        }
        byte[] compressed = Arrays.copyOfRange(raw, 2, raw.length);
        X9ECParameters ecParams = CustomNamedCurves.getByName("P-256");
        if (ecParams == null) {
            ecParams = CustomNamedCurves.getByName("prime256v1");
        }
        ECPoint point = ecParams.getCurve().decodePoint(compressed);
        if (point == null || point.isInfinity() || !point.isValid()) {
            throw new Exception("multikey: invalid P-256 compressed point");
        }
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        return kf.generatePublic(new org.bouncycastle.jce.spec.ECPublicKeySpec(point,
                ECNamedCurveTable.getParameterSpec("prime256v1")));
    }

    public static String encodeP256PublicKey(PublicKey publicKey) throws Exception {
        if (!(publicKey instanceof org.bouncycastle.jce.interfaces.ECPublicKey ec)) {
            throw new Exception("multikey: expected EC public key");
        }
        byte[] compressed = ec.getQ().getEncoded(true);
        byte[] raw = new byte[P256_PUB_MULTICODEC.length + compressed.length];
        System.arraycopy(P256_PUB_MULTICODEC, 0, raw, 0, P256_PUB_MULTICODEC.length);
        System.arraycopy(compressed, 0, raw, P256_PUB_MULTICODEC.length, compressed.length);
        return Multibase.encodeBase58Btc(raw);
    }
}
