package com.pila.credential.common.crypto;

import java.util.Map;

import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Cryptographic operations for credential signing and verification.
 * Note: This is a placeholder. Full implementation requires secp256k1 library.
 */
public class Crypto {

    /**
     * Signs data using ECDSA with secp256k1.
     * 
     * @param signData   The data to sign
     * @param privKeyHex The private key in hex format
     * @return The signature bytes (65 bytes: r, s, v)
     */
    public static byte[] ecdsaSign(byte[] signData, String privKeyHex) throws Exception {
        // TODO: Implement using BouncyCastle or similar secp256k1 library
        throw new UnsupportedOperationException(
                "ECDSA signing not yet implemented. Requires secp256k1 library.");
    }

    private static final String CURVE_NAME = "secp256k1";

    private static final org.bouncycastle.jce.spec.ECParameterSpec CURVE_SPEC;

    static {
        Security.addProvider(new BouncyCastleProvider());
        CURVE_SPEC = ECNamedCurveTable.getParameterSpec(CURVE_NAME);
    }

    private Crypto() {
    }

    /**
     * Verifies an ECDSA signature.
     * 
     * @param publicKeyHex The public key in hex format
     * @param signatureHex The signature in hex format
     * @param message      The message to verify, hashed with SHA-256
     * @return true if signature is valid
     */
    public static boolean ecdsaVerifySignature(
            String publicKeyHex, // 02/03/04 + hex
            String signatureHex, // DER or R||S
            byte[] message // raw bytes
    ) {
        try {
            // 1. Convert public key hex → ECPoint
            byte[] pubBytes = Hex.decode(publicKeyHex);
            ECPoint point = CURVE_SPEC.getCurve().decodePoint(pubBytes);

            // 2. Validate public key
            if (point.isInfinity()) {
                throw new IllegalArgumentException("Public key is point at infinity");
            }
            if (!point.isValid()) {
                throw new IllegalArgumentException("Public key is not on secp256k1 curve");
            }

            if (message.length != 32) {
                throw new IllegalArgumentException("Message must be 32 bytes");
            }

            // 3. Convert ECPoint to PublicKey (BC)
            KeyFactory kf = KeyFactory.getInstance("EC", "BC");
            PublicKey publicKey = kf.generatePublic(new org.bouncycastle.jce.spec.ECPublicKeySpec(point, CURVE_SPEC));

            // 4. Hex signature, 64 (r||s) or 65 (r||s||v) bytes; no DER (Go ECDSAVerifySignature).
            return verifyEcdsaHex(publicKey, signatureHex, message);

        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Go's {@code ECDSAVerifySignature}: a hex signature of exactly 64 or 65 bytes (the recovery byte
     * is dropped) checked over the digest on the key's own curve.
     */
    public static boolean verifyEcdsaHex(java.security.PublicKey publicKey, String signatureHex, byte[] digest32) {
        try {
            byte[] sig = Hex.decode(signatureHex);
            if (sig.length == 65) {
                sig = extract(sig, 0, 64);
            }
            return sig.length == 64 && verifyEcdsaRaw(publicKey, digest32, sig);
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean verifyEcdsaRaw(java.security.PublicKey publicKey, byte[] digest32, byte[] signature64) {
        try {
            if (digest32 == null || digest32.length != 32) {
                return false;
            }
            if (signature64 == null || signature64.length != 64) {
                return false;
            }
            byte[] der = encodeDer(new BigInteger(1, extract(signature64, 0, 32)),
                    new BigInteger(1, extract(signature64, 32, 32)));
            Signature verifier = Signature.getInstance("NONEwithECDSA", "BC");
            verifier.initVerify(publicKey);
            verifier.update(digest32);
            return verifier.verify(der);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Go's {@code VerifyJwtProof}: verifies {@code req.proof.jwt} (a secp256k1 JWT) against {@code pub}.
     * A 65-byte signature must recover to {@code pub}; a 64-byte one must verify under it and be low-S.
     *
     * @throws Exception when the token is missing or malformed (Go returns an error)
     */
    public static boolean verifyJwtProof(Map<String, Object> req, java.security.PublicKey pub) throws Exception {
        Object proof = req.get("proof");
        Object jwt = proof instanceof Map<?, ?> m ? m.get("jwt") : null;
        if (!(jwt instanceof String token) || token.isEmpty()) {
            throw new Exception("JWT token is missing");
        }
        if (pub == null) {
            throw new Exception("public key is nil");
        }
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) {
            throw new Exception("failed to extract signature and message from JWT: invalid JWT format");
        }
        if (parts[2].indexOf('=') >= 0) {
            throw new Exception("failed to extract signature and message from JWT: failed to decode signature");
        }
        byte[] signature;
        try {
            signature = java.util.Base64.getUrlDecoder().decode(parts[2]);
        } catch (IllegalArgumentException e) {
            throw new Exception("failed to extract signature and message from JWT: failed to decode signature", e);
        }
        byte[] message = (parts[0] + "." + parts[1]).getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (!(pub instanceof org.bouncycastle.jce.interfaces.ECPublicKey ec) || !isSecp256k1(ec)) {
            return false;
        }
        byte[] compressed = ec.getQ().getEncoded(true);
        byte[] hash = java.security.MessageDigest.getInstance("SHA-256").digest(message);
        if (signature.length == 65) {
            byte[] recovered = recoverCompressed(hash, signature);
            return recovered != null && java.util.Arrays.equals(recovered, compressed);
        }
        if (signature.length != 64 || message.length == 0) {
            return false;
        }
        // libsecp256k1 verify (go-ethereum VerifySignature) rejects a high-S signature.
        BigInteger s = new BigInteger(1, extract(signature, 32, 32));
        if (s.compareTo(CURVE_SPEC.getN().shiftRight(1)) > 0) {
            return false;
        }
        return verifyEcdsaRaw(pub, hash, signature);
    }

    private static boolean isSecp256k1(org.bouncycastle.jce.interfaces.ECPublicKey k) {
        return k.getParameters().getN().equals(CURVE_SPEC.getN())
                && k.getParameters().getCurve().equals(CURVE_SPEC.getCurve());
    }

    /** go-ethereum {@code Ecrecover}: the compressed public key a 65-byte r||s||v signature recovers to, or null. */
    private static byte[] recoverCompressed(byte[] hash, byte[] sig65) {
        try {
            BigInteger n = CURVE_SPEC.getN();
            BigInteger r = new BigInteger(1, extract(sig65, 0, 32));
            BigInteger s = new BigInteger(1, extract(sig65, 32, 32));
            int v = sig65[64] & 0xff;
            if (v > 3 || r.signum() == 0 || s.signum() == 0 || r.compareTo(n) >= 0 || s.compareTo(n) >= 0) {
                return null;
            }
            BigInteger x = r.add(BigInteger.valueOf(v / 2).multiply(n));
            org.bouncycastle.math.ec.ECCurve curve = CURVE_SPEC.getCurve();
            if (x.compareTo(curve.getField().getCharacteristic()) >= 0) {
                return null;
            }
            byte[] xb = org.bouncycastle.util.BigIntegers.asUnsignedByteArray(32, x);
            byte[] enc = new byte[33];
            enc[0] = (byte) (0x02 | (v & 1));
            System.arraycopy(xb, 0, enc, 1, 32);
            ECPoint rPoint = curve.decodePoint(enc);
            BigInteger e = new BigInteger(1, hash);
            BigInteger rInv = r.modInverse(n);
            BigInteger u1 = n.subtract(e.mod(n)).multiply(rInv).mod(n);
            BigInteger u2 = s.multiply(rInv).mod(n);
            ECPoint q = org.bouncycastle.math.ec.ECAlgorithms
                    .sumOfTwoMultiplies(CURVE_SPEC.getG(), u1, rPoint, u2).normalize();
            return q.isInfinity() ? null : q.getEncoded(true);
        } catch (Exception ex) {
            return null;
        }
    }

    /**
     * Go's {@code VerifyRSAJWS}: RS256/384/512 (PKCS#1 v1.5) and PS256/384/512 (PSS; the salt length is
     * detected, as Go's nil options do). Returns normally on success.
     */
    public static void verifyRsaJws(String alg, java.security.interfaces.RSAPublicKey pub, byte[] signingInput,
            byte[] sig) throws Exception {
        if (pub == null) {
            throw new Exception("nil RSA public key");
        }
        String bits = alg.length() == 5 ? alg.substring(2) : "";
        String hash = switch (bits) {
            case "256" -> "SHA-256";
            case "384" -> "SHA-384";
            case "512" -> "SHA-512";
            default -> null;
        };
        if (hash == null || !(alg.startsWith("RS") || alg.startsWith("PS"))) {
            throw new Exception("unsupported JWS alg: " + alg);
        }
        byte[] digest = java.security.MessageDigest.getInstance(hash).digest(signingInput);
        boolean ok;
        if (alg.startsWith("RS")) {
            Signature v = Signature.getInstance("SHA" + bits + "withRSA");
            v.initVerify(pub);
            v.update(signingInput);
            ok = v.verify(sig);
        } else {
            ok = verifyPssAutoSalt(pub, hash, digest, sig);
        }
        if (!ok) {
            throw new Exception("crypto/rsa: verification error");
        }
    }

    /** RFC 8017 9.1.2 EMSA-PSS-VERIFY with MGF1 over the same hash and the salt length read from the encoding. */
    private static boolean verifyPssAutoSalt(java.security.interfaces.RSAPublicKey pub, String hashName,
            byte[] mHash, byte[] sig) throws Exception {
        BigInteger n = pub.getModulus();
        int k = (n.bitLength() + 7) / 8;
        if (sig.length != k) {
            return false;
        }
        BigInteger sInt = new BigInteger(1, sig);
        if (sInt.compareTo(n) >= 0) {
            return false;
        }
        int emBits = n.bitLength() - 1;
        int emLen = (emBits + 7) / 8;
        byte[] full = org.bouncycastle.util.BigIntegers.asUnsignedByteArray(k, sInt.modPow(pub.getPublicExponent(), n));
        byte[] em = extract(full, k - emLen, emLen);
        int hLen = mHash.length;
        if (emLen < hLen + 2 || (em[emLen - 1] & 0xff) != 0xbc) {
            return false;
        }
        byte[] maskedDb = extract(em, 0, emLen - hLen - 1);
        byte[] h = extract(em, emLen - hLen - 1, hLen);
        int topBits = 8 * emLen - emBits;
        if (topBits > 0 && (maskedDb[0] & ((0xff << (8 - topBits)) & 0xff)) != 0) {
            return false;
        }
        MessageDigest md = MessageDigest.getInstance(hashName);
        byte[] db = new byte[maskedDb.length];
        for (int i = 0, ctr = 0; i < db.length; ctr++) {
            md.update(h);
            md.update(new byte[] {(byte) (ctr >>> 24), (byte) (ctr >>> 16), (byte) (ctr >>> 8), (byte) ctr});
            byte[] block = md.digest();
            for (int j = 0; j < block.length && i < db.length; j++, i++) {
                db[i] = (byte) (maskedDb[i] ^ block[j]);
            }
        }
        if (topBits > 0) {
            db[0] &= (byte) (0xff >>> topBits);
        }
        int i = 0;
        while (i < db.length && db[i] == 0) {
            i++;
        }
        if (i == db.length || db[i] != 0x01) {
            return false;
        }
        byte[] salt = extract(db, i + 1, db.length - i - 1);
        md.update(new byte[8]);
        md.update(mHash);
        md.update(salt);
        return java.util.Arrays.equals(md.digest(), h);
    }

    /**
     * Verifies a JSON signature.
     * 
     * @param publicKeyBytes The public key bytes
     * @param message        The message bytes
     * @param signatureBytes The signature bytes
     * @return true if signature is valid
     */
    public static boolean verifyJSONSignature(byte[] publicKeyBytes, byte[] message, byte[] signatureBytes) {
        // TODO: Implement JSON signature verification
        throw new UnsupportedOperationException(
                "JSON signature verification not yet implemented.");
    }

    /**
     * Converts a key string to bytes.
     * 
     * @param keyHex The key in hex format (with or without 0x prefix)
     * @return The key bytes
     */
    public static byte[] keyToBytes(String keyHex) throws Exception {
        if (keyHex == null || keyHex.isEmpty()) {
            throw new IllegalArgumentException("key is not in hex format");
        }

        String hex = keyHex.startsWith("0x") ? keyHex.substring(2) : keyHex;

        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Invalid hex string length");
        }

        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            bytes[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return bytes;
    }

    // ----------------- Helper functions -----------------

    private static boolean isDer(byte[] sig) {
        return sig.length > 0 && sig[0] == 0x30;
    }

    private static byte[] rawToDer(byte[] raw) {
        BigInteger r = new BigInteger(1, extract(raw, 0, 32));
        BigInteger s = new BigInteger(1, extract(raw, 32, 32));
        return encodeDer(r, s);
    }

    private static byte[] extract(byte[] src, int start, int len) {
        byte[] out = new byte[len];
        System.arraycopy(src, start, out, 0, len);
        return out;
    }

    private static byte[] encodeDer(BigInteger r, BigInteger s) {
        byte[] rBytes = trimLeadingZeros(r.toByteArray());
        byte[] sBytes = trimLeadingZeros(s.toByteArray());
        int length = 2 + rBytes.length + 2 + sBytes.length;
        byte[] seq = new byte[2 + length];
        int idx = 0;
        seq[idx++] = 0x30;
        seq[idx++] = (byte) length;
        seq[idx++] = 0x02;
        seq[idx++] = (byte) rBytes.length;
        System.arraycopy(rBytes, 0, seq, idx, rBytes.length);
        idx += rBytes.length;
        seq[idx++] = 0x02;
        seq[idx++] = (byte) sBytes.length;
        System.arraycopy(sBytes, 0, seq, idx, sBytes.length);
        return seq;
    }

    private static byte[] trimLeadingZeros(byte[] v) {
        int i = 0;
        while (i < v.length - 1 && v[i] == 0) {
            i++;
        }
        if ((v[i] & 0x80) != 0) {
            byte[] extended = new byte[v.length - i + 1];
            System.arraycopy(v, i, extended, 1, extended.length - 1);
            return extended;
        }
        byte[] trimmed = new byte[v.length - i];
        System.arraycopy(v, i, trimmed, 0, trimmed.length);
        return trimmed;
    }

}
