package com.pila.credential.common.ecdsasd;

import com.pila.credential.common.crypto.Crypto;
import com.pila.credential.common.util.Multibase;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;

public final class Keys {

    static final byte[] P256_PRIV_MULTICODEC = new byte[] { (byte) 0x86, 0x26 };
    private static final byte[] P256_PUB_MULTICODEC = new byte[] { (byte) 0x80, 0x24 };

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private Keys() {
    }

    public static byte[] pubToMultikeyBytes(PublicKey pub) throws Exception {
        if (!(pub instanceof ECPublicKey ec)) {
            throw new Exception("multikey: expected EC public key");
        }
        byte[] compressed = ec.getQ().getEncoded(true);
        byte[] raw = new byte[P256_PUB_MULTICODEC.length + compressed.length];
        System.arraycopy(P256_PUB_MULTICODEC, 0, raw, 0, P256_PUB_MULTICODEC.length);
        System.arraycopy(compressed, 0, raw, P256_PUB_MULTICODEC.length, compressed.length);
        return raw;
    }

    public static PublicKey ecPubFromMultikeyBytes(byte[] raw) throws Exception {
        if (raw.length < 3 || raw[0] != P256_PUB_MULTICODEC[0]
                || raw[1] != P256_PUB_MULTICODEC[1]) {
            throw new Exception("multikey: not a p256-pub multikey");
        }
        byte[] compressed = Arrays.copyOfRange(raw, 2, raw.length);
        X9ECParameters ecParams = CustomNamedCurves.getByName("P-256");
        if (ecParams == null) {
            ecParams = CustomNamedCurves.getByName("prime256v1");
        }
        ECPoint point = ecParams.getCurve().decodePoint(compressed);
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        return kf.generatePublic(new org.bouncycastle.jce.spec.ECPublicKeySpec(point,
                ECNamedCurveTable.getParameterSpec("prime256v1")));
    }

    public static String encodeMultibaseKey(byte[] raw) throws Exception {
        return Multibase.encodeBase58Btc(raw);
    }

    public static byte[] decodeMultibaseKey(String multibase) throws Exception {
        return Multibase.decodeBase58Btc(multibase);
    }

    public static PrivateKey decodeP256PrivMultibase(String multibase) throws Exception {
        byte[] raw = decodeMultibaseKey(multibase);
        if (raw.length < P256_PRIV_MULTICODEC.length + 32
                || raw[0] != P256_PRIV_MULTICODEC[0] || raw[1] != P256_PRIV_MULTICODEC[1]) {
            throw new Exception("multikey: not a p256-priv multikey");
        }
        byte[] dBytes = Arrays.copyOfRange(raw, P256_PRIV_MULTICODEC.length, P256_PRIV_MULTICODEC.length + 32);
        BigInteger d = new BigInteger(1, dBytes);
        var spec = ECNamedCurveTable.getParameterSpec("prime256v1");
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        return kf.generatePrivate(new ECPrivateKeySpec(d, spec));
    }

    public static EphemeralKey newEphemeralKey() throws Exception {
        return new EphemeralKey(null);
    }

    public static final class EphemeralKey {
        private final PrivateKey priv;

        EphemeralKey(PrivateKey existing) throws Exception {
            if (existing != null) {
                this.priv = existing;
                return;
            }
            var spec = ECNamedCurveTable.getParameterSpec("prime256v1");
            var gen = java.security.KeyPairGenerator.getInstance("EC", "BC");
            gen.initialize(spec, new SecureRandom());
            this.priv = gen.generateKeyPair().getPrivate();
        }

        public byte[] signStatement(String statement) throws Exception {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(statement.getBytes(StandardCharsets.UTF_8));
            Signature sig = Signature.getInstance("NONEwithECDSA", "BC");
            sig.initSign(priv);
            sig.update(digest);
            byte[] der = sig.sign();
            return normalizeLowS(derToRaw64(der));
        }

        public PublicKey publicKey() throws Exception {
            if (!(priv instanceof org.bouncycastle.jce.interfaces.ECPrivateKey ec)) {
                throw new Exception("expected BC EC private key");
            }
            KeyFactory kf = KeyFactory.getInstance("EC", "BC");
            return kf.generatePublic(new org.bouncycastle.jce.spec.ECPublicKeySpec(
                    ec.getParameters().getG().multiply(ec.getD()).normalize(),
                    ec.getParameters()));
        }
    }

    static boolean verifyP256(PublicKey pub, byte[] digest, byte[] sig64) {
        return Crypto.verifyEcdsaRaw(pub, digest, sig64);
    }

    private static byte[] derToRaw64(byte[] der) throws Exception {
        org.bouncycastle.asn1.ASN1Sequence seq = (org.bouncycastle.asn1.ASN1Sequence) org.bouncycastle.asn1.ASN1Sequence
                .fromByteArray(der);
        BigInteger r = ((org.bouncycastle.asn1.ASN1Integer) seq.getObjectAt(0)).getPositiveValue();
        BigInteger s = ((org.bouncycastle.asn1.ASN1Integer) seq.getObjectAt(1)).getPositiveValue();
        byte[] out = new byte[64];
        System.arraycopy(toFixed32(r.toByteArray()), 0, out, 0, 32);
        System.arraycopy(toFixed32(s.toByteArray()), 0, out, 32, 32);
        return out;
    }

    private static byte[] normalizeLowS(byte[] sig64) {
        var spec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("prime256v1");
        BigInteger halfN = spec.getN().shiftRight(1);
        BigInteger s = new BigInteger(1, sig64, 32, 32);
        if (s.compareTo(halfN) <= 0) {
            return sig64;
        }
        BigInteger n = spec.getN();
        BigInteger lowS = n.subtract(s);
        byte[] out = Arrays.copyOf(sig64, 64);
        System.arraycopy(toFixed32(lowS.toByteArray()), 0, out, 32, 32);
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
