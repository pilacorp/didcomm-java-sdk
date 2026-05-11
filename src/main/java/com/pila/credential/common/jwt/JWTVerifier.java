package com.pila.credential.common.jwt;

import com.pila.credential.common.crypto.Crypto;
import com.pila.credential.common.verificationmethod.VerificationMethodResolver;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

/**
 * JWT verifier for ES256K algorithm.
 */
public class JWTVerifier {
    private VerificationMethodResolver resolver;

    /**
     * Creates a new JWT verifier with DID resolver.
     * 
     * @param didBaseURL The base URL for DID resolution
     */
    public JWTVerifier(String didBaseURL) {
        this.resolver = new VerificationMethodResolver(didBaseURL);
    }

    /**
     * Verifies a JWT token.
     * 
     * @param tokenString The JWT token string
     * @throws Exception if verification fails
     */
    public void verifyJWT(String tokenString) throws Exception {
        String[] parts = tokenString.split("\\.");
        if (parts.length != 3) {
            throw new Exception("invalid JWT format");
        }

        // Decode header to get kid
        byte[] headerBytes = Base64.getUrlDecoder().decode(parts[0]);
        String headerJson = new String(headerBytes, StandardCharsets.UTF_8);

        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        @SuppressWarnings("unchecked")
        java.util.Map<String, Object> header = mapper.readValue(headerJson, java.util.Map.class);

        // Check algorithm
        Object algObj = header.get("alg");
        if (!(algObj instanceof String) || !"ES256K".equals(algObj)) {
            throw new Exception("unsupported algorithm: " + algObj);
        }

        // Get kid
        Object kidObj = header.get("kid");
        if (!(kidObj instanceof String)) {
            throw new Exception("kid not found in header");
        }
        String kid = (String) kidObj;

        // Get public key from resolver
        String publicKeyHex = resolver.getPublicKey(kid);
        if (publicKeyHex == null || publicKeyHex.isEmpty()) {
            throw new Exception("failed to get public key");
        }

        // Get signing string and signature
        String signingString = parts[0] + "." + parts[1];
        byte[] signatureBytes = Base64.getUrlDecoder().decode(parts[2]);

        // Verify signature
        if (signatureBytes.length == 65) {
            signatureBytes = Arrays.copyOf(signatureBytes, 64);
        } else if (signatureBytes.length != 64) {
            throw new Exception("invalid signature length: got " + signatureBytes.length + ", want 64 or 65");
        }

        // Hash the signing string with SHA-256
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] messageHash = digest.digest(signingString.getBytes(StandardCharsets.UTF_8));

        // Convert signature to hex format (R||S)
        String signatureHex = Hex.toHexString(signatureBytes);

        // Verify using Crypto utility
        boolean isValid = Crypto.ecdsaVerifySignature(publicKeyHex, signatureHex, messageHash);
        if (!isValid) {
            throw new Exception("signature verification failed");
        }
    }
}
