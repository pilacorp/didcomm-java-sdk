package com.pila.credential.common.jwt;

import com.pila.credential.common.signer.DefaultSignerProvider;
import com.pila.credential.common.signer.SignerProvider;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.security.MessageDigest;

/**
 * JWT signer for ES256K algorithm.
 */
public class JWTSigner {
    private final SignerProvider signerProvider;

    /**
     * Creates a new JWT signer instance.
     * 
     * @param privKeyHex The private key in hex format
     */
    public JWTSigner(String privKeyHex) {
        try {
            this.signerProvider = new DefaultSignerProvider(privKeyHex);
        } catch (Exception e) {
            throw new IllegalArgumentException("invalid privKeyHex: " + e.getMessage(), e);
        }
    }

    public JWTSigner(SignerProvider signerProvider) {
        if (signerProvider == null) {
            throw new IllegalArgumentException("signerProvider cannot be null");
        }
        this.signerProvider = signerProvider;
    }

    /**
     * Signs a string and returns the base64url-encoded signature.
     * 
     * @param signingString The string to sign
     * @return The base64url-encoded signature
     * @throws Exception if signing fails
     */
    public String signString(String signingString) throws Exception {
        if (signingString == null) {
            throw new IllegalArgumentException("signingString cannot be null");
        }

        byte[] bytes = signingString.getBytes(StandardCharsets.UTF_8);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] digest32 = digest.digest(bytes);

        byte[] sig = signerProvider.sign(digest32);
        byte[] sig64 = normalizeJwtSignature(sig);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sig64);
    }

    public static byte[] normalizeJwtSignature(byte[] signatureBytes) {
        if (signatureBytes == null) {
            throw new IllegalArgumentException("signature cannot be null");
        }
        if (signatureBytes.length == 64) {
            return signatureBytes;
        }
        if (signatureBytes.length == 65) {
            byte[] out = new byte[64];
            System.arraycopy(signatureBytes, 0, out, 0, 64);
            return out;
        }
        throw new IllegalArgumentException("signature length must be 64 or 65");
    }
}
