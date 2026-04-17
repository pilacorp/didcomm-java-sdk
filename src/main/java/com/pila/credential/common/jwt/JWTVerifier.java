package com.pila.credential.common.jwt;

import com.pila.credential.common.crypto.Crypto;
import com.pila.credential.common.verificationmethod.VerificationMethodResolver;
import com.pila.credential.common.verificationmethod.VerificationMethodResolverProvider;
import com.pila.credential.vc.CredentialConfig;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * JWT verifier for ES256K algorithm.
 */
public class JWTVerifier {

    private static final com.fasterxml.jackson.databind.ObjectMapper MAPPER =
            new com.fasterxml.jackson.databind.ObjectMapper();

    private final VerificationMethodResolverProvider resolver;

    /**
     * Creates a new JWT verifier with DID resolver.
     *
     * @param didBaseURL The base URL for DID resolution
     */
    public JWTVerifier(String didBaseURL) {
        VerificationMethodResolverProvider configuredResolver =
                CredentialConfig.getVerificationMethodResolverProvider();
        if (configuredResolver != null) {
            this.resolver = configuredResolver;
        } else {
            this.resolver = new VerificationMethodResolver(didBaseURL);
        }
    }

    /**
     * Creates a new JWT verifier with a custom verification method resolver.
     *
     * @param resolver custom resolver implementation
     */
    public JWTVerifier(VerificationMethodResolverProvider resolver) {
        if (resolver == null) {
            throw new IllegalArgumentException("resolver cannot be null");
        }
        this.resolver = resolver;
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

        @SuppressWarnings("unchecked")
        java.util.Map<String, Object> header = MAPPER.readValue(headerJson, java.util.Map.class);

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

        // Hash the signing string with SHA-256
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] messageHash = digest.digest(signingString.getBytes(StandardCharsets.UTF_8));

        // Verify using Crypto utility; it accepts DER or raw R||S signatures.
        String signatureHex = Hex.toHexString(signatureBytes);
        boolean isValid;
        try {
            isValid = Crypto.ecdsaVerifySignature(publicKeyHex, signatureHex, messageHash);
        } catch (RuntimeException e) {
            throw new Exception("VC JWT signature verification failed: " + e.getMessage(), e);
        }
        if (!isValid) {
            throw new Exception("VC JWT signature verification failed");
        }
    }
}
