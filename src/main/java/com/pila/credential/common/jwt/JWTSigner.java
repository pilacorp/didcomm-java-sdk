package com.pila.credential.common.jwt;

import com.starkbank.ellipticcurve.Ecdsa;
import com.starkbank.ellipticcurve.PrivateKey;
import com.starkbank.ellipticcurve.Signature;

import java.util.Base64;

/**
 * JWT signer for ES256K algorithm.
 */
public class JWTSigner {
    private String privKeyHex;

    /**
     * Creates a new JWT signer instance.
     * 
     * @param privKeyHex The private key in hex format
     */
    public JWTSigner(String privKeyHex) {
        this.privKeyHex = privKeyHex;
    }

    /**
     * Signs a string and returns the base64url-encoded signature.
     * 
     * @param signingString The string to sign
     * @return The base64url-encoded signature
     * @throws Exception if signing fails
     */
    public String signString(String signingString) throws Exception {
        // Convert hex private key to PrivateKey object
        PrivateKey privateKey = PrivateKey.fromString(privKeyHex);

        // Sign the message
        Signature signature = Ecdsa.sign(signingString, privateKey);

        // Get R and S values
        byte[] r = signature.r.toByteArray();
        byte[] s = signature.s.toByteArray();

        // Ensure R and S are 32 bytes each (pad with leading zeros if needed)
        byte[] rPadded = new byte[32];
        byte[] sPadded = new byte[32];
        int rOffset = Math.max(0, 32 - r.length);
        int sOffset = Math.max(0, 32 - s.length);
        System.arraycopy(r, 0, rPadded, rOffset, Math.min(32, r.length));
        System.arraycopy(s, 0, sPadded, sOffset, Math.min(32, s.length));

        // Concatenate R and S (64 bytes total)
        byte[] signatureBytes = new byte[64];
        System.arraycopy(rPadded, 0, signatureBytes, 0, 32);
        System.arraycopy(sPadded, 0, signatureBytes, 32, 32);

        // Encode as base64url
        return Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);
    }
}
