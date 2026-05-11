package com.pila.credential.vc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.dto.Proof;
import com.pila.credential.common.jsonmap.JSONMap;
import com.pila.credential.common.jwt.JWTSigner;
import com.pila.credential.common.jwt.JWTVerifier;
import com.pila.credential.common.signer.DefaultSignerProvider;
import com.pila.credential.common.signer.SignerProvider;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * JWTCredential represents a verifiable credential in JWT format.
 */
public class JWTCredential implements Credential {
    private String signingInput; // JWT header.payload (base64 encoded)
    private CredentialData payloadData; // Parsed payload as CredentialData
    private String signature; // JWT signature (if signed)
    private String verificationMethodKey; // Verification method key

    private static final String DEFAULT_VERIFICATION_METHOD_KEY = "key-1";

    private JWTCredential() {
        this.verificationMethodKey = DEFAULT_VERIFICATION_METHOD_KEY;
    }

    /**
     * Creates a new JWTCredential from CredentialContents.
     * 
     * @param vcc The credential contents
     * @return A new JWTCredential instance
     * @throws Exception if creation fails
     */
    public static JWTCredential newJWTCredential(CredentialContents vcc) throws Exception {
        // Convert CredentialContents to CredentialData
        CredentialData m = CredentialHelper.serializeCredentialContents(vcc);
        CredentialData payloadData = m;

        // Extract other claims from credentialContents
        Map<String, Object> otherClaims = new HashMap<>();
        if (vcc.getIssuer() != null && !vcc.getIssuer().isEmpty()) {
            otherClaims.put("iss", vcc.getIssuer());
        }
        if (vcc.getSubject() != null && !vcc.getSubject().isEmpty() && vcc.getSubject().get(0).getId() != null) {
            otherClaims.put("sub", vcc.getSubject().get(0).getId());
        }
        if (vcc.getValidUntil() != null) {
            otherClaims.put("exp", vcc.getValidUntil().getEpochSecond());
        }
        if (vcc.getValidFrom() != null) {
            long epochSecond = vcc.getValidFrom().getEpochSecond();
            otherClaims.put("iat", epochSecond);
            otherClaims.put("nbf", epochSecond);
        }
        if (vcc.getId() != null && !vcc.getId().isEmpty()) {
            otherClaims.put("jti", vcc.getId());
        }

        // Build payload with vc claim and other claims
        Map<String, Object> payload = new HashMap<>();
        payload.put("vc", payloadData);
        // Add other claims to payload
        payload.putAll(otherClaims);

        // Build header
        String verificationMethodKey = DEFAULT_VERIFICATION_METHOD_KEY;
        Map<String, Object> header = new HashMap<>();
        header.put("typ", "JWT");
        header.put("alg", "ES256K");
        header.put("kid", vcc.getIssuer() + "#" + verificationMethodKey);

        // Encode header and payload
        ObjectMapper mapper = new ObjectMapper();
        byte[] headerJSON = mapper.writeValueAsBytes(header);
        String headerEncoded = Base64.getUrlEncoder().withoutPadding().encodeToString(headerJSON);

        byte[] payloadJSON = mapper.writeValueAsBytes(payload);
        String payloadEncoded = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJSON);

        // Create signing input (header.payload)
        String signingInput = headerEncoded + "." + payloadEncoded;

        JWTCredential jwtCred = new JWTCredential();
        jwtCred.signingInput = signingInput;
        jwtCred.payloadData = payloadData;
        jwtCred.signature = "";
        jwtCred.verificationMethodKey = verificationMethodKey;

        return jwtCred;
    }

    /**
     * Parses a JWTCredential from a raw JWT string.
     * 
     * @param rawJWT The raw JWT string
     * @return A parsed JWTCredential instance
     * @throws Exception if parsing fails
     */
    public static JWTCredential parseJWTCredential(String rawJWT) throws Exception {
        if (!CredentialParser.isJWTCredential(rawJWT)) {
            throw new Exception("invalid JWT format");
        }

        // Remove surrounding quotes if present
        rawJWT = rawJWT.trim();
        if (rawJWT.startsWith("\"") && rawJWT.endsWith("\"")) {
            rawJWT = rawJWT.substring(1, rawJWT.length() - 1);
        }

        // Split JWT into parts
        String[] parts = rawJWT.split("\\.");
        if (parts.length < 2) {
            throw new Exception("invalid JWT format");
        }

        // Extract the payload and header
        String headerEncoded = parts[0];
        String payloadEncoded = parts[1];
        String signature = "";
        if (parts.length == 3) {
            signature = parts[2];
        }

        // Decode the payload
        byte[] payloadBytes = Base64.getUrlDecoder().decode(payloadEncoded);
        ObjectMapper mapper = new ObjectMapper();
        @SuppressWarnings("unchecked")
        Map<String, Object> payloadMap = mapper.readValue(payloadBytes, Map.class);

        // Store the vc claim in payload as payloadData
        Object vcData = payloadMap.get("vc");
        if (vcData == null) {
            throw new Exception("vc claim not found in JWT payload");
        }

        if (!(vcData instanceof Map)) {
            throw new Exception("vc claim is not a valid JSON object");
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> vcMap = (Map<String, Object>) vcData;

        // Create signing input (header.payload)
        String signingInput = headerEncoded + "." + payloadEncoded;

        JWTCredential jwtCred = new JWTCredential();
        jwtCred.signingInput = signingInput;
        jwtCred.payloadData = new CredentialData(vcMap);
        jwtCred.signature = signature;

        return jwtCred;
    }

    @Override
    public void addProof(String privKeyHex) throws Exception {
        addProofByProvider(new DefaultSignerProvider(privKeyHex));
    }

    @Override
    public void addProofByProvider(SignerProvider signerProvider) throws Exception {
        JWTSigner signer = new JWTSigner(signerProvider);
        String newSignature = signer.signString(signingInput);

        // Verify-after-sign (atomic): verify before mutating credential state.
        String didBaseURL = CredentialConfig.getBaseURL();
        JWTVerifier verifier = new JWTVerifier(didBaseURL);
        verifier.verifyJWT(signingInput + "." + newSignature);

        this.signature = newSignature;
    }

    @Override
    public byte[] getSigningInput() throws Exception {
        return signingInput.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public void addCustomProof(Proof proof) throws Exception {
        if (proof == null) {
            throw new IllegalArgumentException("proof cannot be null");
        }

        if (proof.getSignature() == null || proof.getSignature().length == 0) {
            throw new Exception("proof signature cannot be empty");
        }

        byte[] sig64 = JWTSigner.normalizeJwtSignature(proof.getSignature());
        this.signature = Base64.getUrlEncoder().withoutPadding().encodeToString(sig64);
    }

    @Override
    public void verify() throws Exception {
        if (signature == null || signature.isEmpty()) {
            throw new Exception("credential has no signature");
        }

        String didBaseURL = CredentialConfig.getBaseURL();
        JWTVerifier verifier = new JWTVerifier(didBaseURL);
        String serialized = (String) serialize();
        verifier.verifyJWT(serialized);
    }

    @Override
    public Object serialize() throws Exception {
        if (signature != null && !signature.isEmpty()) {
            // Signed JWT
            return signingInput + "." + signature;
        } else {
            // Unsigned JWT
            return signingInput;
        }
    }

    @Override
    public byte[] getContents() throws Exception {
        return ((JSONMap) payloadData).toJSON();
    }

    @Override
    public String getType() {
        return "JWT";
    }

    /**
     * Gets the credential data.
     */
    public CredentialData getPayloadData() {
        return payloadData;
    }

    /**
     * Gets the verification method key.
     */
    public String getVerificationMethodKey() {
        return verificationMethodKey;
    }

    /**
     * Sets the verification method key.
     */
    public void setVerificationMethodKey(String verificationMethodKey) {
        this.verificationMethodKey = verificationMethodKey;
    }
}
