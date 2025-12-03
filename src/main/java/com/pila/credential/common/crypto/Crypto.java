package com.pila.credential.common.crypto;

import java.util.Map;

import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.KeyFactory;
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

            // 4. Decode signature
            byte[] signature = Hex.decode(signatureHex);

            // if signature is 65 bytes
            if (signature.length == 65) {
                signature = extract(signature, 0, 64);
            }

            // Convert raw R||S → DER if needed
            if (!isDer(signature)) {
                signature = rawToDer(signature);
            }

            // 5. Verify signature using SHA-256 + ECDSA
            Signature verifier = Signature.getInstance("NONEwithECDSA", "BC");
            verifier.initVerify(publicKey);
            verifier.update(message);
            return verifier.verify(signature);

        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Verifies a JWT proof.
     * 
     * @param req          The request map containing the proof
     * @param publicKeyHex The public key in hex format
     * @return true if JWT proof is valid
     */
    public static boolean verifyJwtProof(Map<String, Object> req, String publicKeyHex) throws Exception {
        // TODO: Implement JWT proof verification
        throw new UnsupportedOperationException(
                "JWT proof verification not yet implemented.");
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
