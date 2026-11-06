package com.pila.credential.common.signer;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAKey;
import java.util.Arrays;

/**
 * Signs a digest with an RSA key for JsonWebSignature2020, with an in-memory key or a callback (HSM/KMS). The
 * JOSE algorithm (RS256/384/512, PS256/384/512) is declared via {@link #algorithm()} so the SDK hashes the
 * signing input with the matching SHA and writes the JWS header (Go RSAProvider / NewRSAProvider / NewRSAFunc).
 */
public final class RSASignerProvider implements SignerProvider, AlgorithmProvider {
    private final SignerFunction signFn;
    private final String alg;

    /** In-memory key; {@code alg} defaults to RS256 when null or empty. */
    public RSASignerProvider(PrivateKey priv, String alg) {
        if (priv == null) {
            throw new IllegalArgumentException("rsa private key is nil");
        }
        this.alg = jwsAlg(alg);
        hashName(this.alg);
        this.signFn = digest -> signDigest(this.alg, priv, digest);
    }

    public RSASignerProvider(PrivateKey priv) {
        this(priv, null);
    }

    private RSASignerProvider(SignerFunction fn, String alg) {
        this.signFn = fn;
        this.alg = jwsAlg(alg);
    }

    /** Delegates to {@code signFn}: it receives the digest (already hashed with alg's SHA) and returns the signature. */
    public static RSASignerProvider fromFunc(SignerFunction signFn, String alg) {
        if (signFn == null) {
            throw new IllegalArgumentException("sign function is nil");
        }
        return new RSASignerProvider(signFn, alg);
    }

    @Override
    public String algorithm() {
        return alg;
    }

    @Override
    public byte[] sign(byte[] digest) throws Exception {
        return signFn.sign(digest);
    }

    private static String jwsAlg(String alg) {
        return alg == null || alg.isEmpty() ? "RS256" : alg;
    }

    /** JCA digest name for a JOSE RSA alg. */
    public static String hashName(String alg) {
        return switch (alg) {
            case "RS256", "PS256" -> "SHA-256";
            case "RS384", "PS384" -> "SHA-384";
            case "RS512", "PS512" -> "SHA-512";
            default -> throw new IllegalArgumentException("unsupported JWS alg: " + alg);
        };
    }

    private static byte[] signDigest(String alg, PrivateKey priv, byte[] digest) throws Exception {
        String hash = hashName(alg);
        if (alg.startsWith("RS")) {
            Signature s = Signature.getInstance("NONEwithRSA");
            s.initSign(priv);
            s.update(digestInfo(hash, digest));
            return s.sign();
        }
        return pssSign(hash, priv, digest);
    }

    /** DER DigestInfo prefix || digest (RFC 8017 section 9.2). */
    private static byte[] digestInfo(String hash, byte[] digest) {
        byte[] prefix = switch (hash) {
            case "SHA-256" -> new byte[] { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03,
                    0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };
            case "SHA-384" -> new byte[] { 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03,
                    0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30 };
            default -> new byte[] { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03,
                    0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 };
        };
        byte[] out = Arrays.copyOf(prefix, prefix.length + digest.length);
        System.arraycopy(digest, 0, out, prefix.length, digest.length);
        return out;
    }

    /** RSASSA-PSS over a pre-hashed digest, salt as long as possible (Go PSSSaltLengthAuto), MGF1 with the same hash. */
    private static byte[] pssSign(String hash, PrivateKey priv, byte[] mHash) throws Exception {
        int modBits = ((RSAKey) priv).getModulus().bitLength();
        int emBits = modBits - 1;
        int emLen = (emBits + 7) / 8;
        int hLen = mHash.length;
        int sLen = emLen - hLen - 2;
        if (sLen < 0) {
            throw new IllegalArgumentException("rsa key too small for PSS");
        }
        byte[] salt = new byte[sLen];
        new SecureRandom().nextBytes(salt);
        MessageDigest md = MessageDigest.getInstance(hash);
        md.update(new byte[8]);
        md.update(mHash);
        md.update(salt);
        byte[] h = md.digest();
        byte[] db = new byte[emLen - hLen - 1];
        db[db.length - sLen - 1] = 0x01;
        System.arraycopy(salt, 0, db, db.length - sLen, sLen);
        byte[] mask = mgf1(hash, h, db.length);
        for (int i = 0; i < db.length; i++) {
            db[i] ^= mask[i];
        }
        db[0] &= (byte) (0xff >>> (8 * emLen - emBits));
        byte[] em = new byte[emLen];
        System.arraycopy(db, 0, em, 0, db.length);
        System.arraycopy(h, 0, em, db.length, hLen);
        em[emLen - 1] = (byte) 0xbc;
        Cipher raw = Cipher.getInstance("RSA/ECB/NoPadding");
        raw.init(Cipher.ENCRYPT_MODE, priv);
        byte[] sig = raw.doFinal(em);
        int k = (modBits + 7) / 8;
        if (sig.length == k) {
            return sig;
        }
        byte[] out = new byte[k];
        BigInteger v = new BigInteger(1, sig);
        byte[] b = v.toByteArray();
        System.arraycopy(b, Math.max(0, b.length - k), out, k - Math.min(b.length, k), Math.min(b.length, k));
        return out;
    }

    private static byte[] mgf1(String hash, byte[] seed, int len) throws Exception {
        MessageDigest md = MessageDigest.getInstance(hash);
        byte[] out = new byte[len];
        int off = 0;
        for (int counter = 0; off < len; counter++) {
            md.update(seed);
            md.update(new byte[] { (byte) (counter >>> 24), (byte) (counter >>> 16), (byte) (counter >>> 8),
                    (byte) counter });
            byte[] block = md.digest();
            int n = Math.min(block.length, len - off);
            System.arraycopy(block, 0, out, off, n);
            off += n;
        }
        return out;
    }
}
