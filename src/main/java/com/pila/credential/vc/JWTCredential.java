package com.pila.credential.vc;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.dto.Proof;
import com.pila.credential.common.error.CredentialException;
import com.pila.credential.common.error.SDJWTRequiresJOSEException;
import com.pila.credential.common.jsonmap.JSONMap;
import com.pila.credential.common.jwt.JWTVerifier;
import com.pila.credential.common.jwt.SigningKey;
import com.pila.credential.common.sdjwt.DecodedDisclosure;
import com.pila.credential.common.signer.DefaultSignerProvider;
import com.pila.credential.common.signer.SignerProvider;
import com.pila.credential.common.util.Vcdm;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * JWTCredential represents a VC 1.1 style credential in JWT format (typ JWT, claims under {@code vc}).
 * Selective disclosure is not supported here: it is refused with {@link SDJWTRequiresJOSEException}; use
 * {@link JOSECredential} (vc+sd-jwt).
 */
public class JWTCredential implements SignableCredential {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private String signingInput; // header.payload (base64url)
    private CredentialData payloadData; // the vc claim
    private Map<String, Object> jwtClaims = new LinkedHashMap<>(); // top-level claims (iss, sub, exp, nbf, iat, jti)
    private String signature = "";
    private SigningKey signingKey = SigningKey.NONE; // VM the header names; NONE for a parsed credential

    private JWTCredential() {
    }

    public static JWTCredential newJWTCredential(CredentialContents vcc) throws Exception {
        return newJWTCredential(vcc, null);
    }

    /**
     * Builds the unsigned token. The header's {@code kid} is the pinned VM ({@code withVerificationMethodKey}) or
     * the issuer's latest active assertionMethod VM, and {@code alg} follows that VM's key (ES256 for P-256,
     * ES256K for secp256k1), both resolved through the call's resolver.
     */
    public static JWTCredential newJWTCredential(CredentialContents vcc, CredentialOptions opts) throws Exception {
        CredentialOptions o = CredentialOptions.orEmpty(opts);
        // Refused before anything is built and before the DID is resolved: no network round trip for a call that
        // cannot succeed.
        if (o.hasSDOptions()) {
            throw new SDJWTRequiresJOSEException("newJWTCredential");
        }
        CredentialData m = CredentialHelper.serializeCredentialContents(vcc);
        Map<String, Object> vcMap = MAPPER.readValue(MAPPER.writeValueAsBytes(m),
                new TypeReference<LinkedHashMap<String, Object>>() {
                });
        if (CredentialSupport.carriesSDJWT(vcMap)) {
            throw new SDJWTRequiresJOSEException("newJWTCredential: contents carry SD-JWT digests");
        }

        Map<String, Object> claims = new LinkedHashMap<>();
        if (vcc.getIssuer() != null && !vcc.getIssuer().isEmpty()) {
            claims.put("iss", vcc.getIssuer());
        }
        if (vcc.getSubject() != null && !vcc.getSubject().isEmpty() && vcc.getSubject().get(0).getId() != null
                && !vcc.getSubject().get(0).getId().isEmpty()) {
            claims.put("sub", vcc.getSubject().get(0).getId());
        }
        if (vcc.getValidUntil() != null) {
            claims.put("exp", vcc.getValidUntil().getEpochSecond());
        }
        if (vcc.getValidFrom() != null) {
            long epochSecond = vcc.getValidFrom().getEpochSecond();
            claims.put("iat", epochSecond);
            claims.put("nbf", epochSecond);
        }
        if (vcc.getId() != null && !vcc.getId().isEmpty()) {
            claims.put("jti", vcc.getId());
        }

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("vc", vcMap);
        payload.putAll(claims);

        // Resolve the VM so alg reflects the key it holds and a missing or ungranted kid is caught here.
        SigningKey key = SigningKey.resolve(vcc.getIssuer(), "assertionMethod", o.getVerificationMethodKey(),
                o.effectiveResolver());
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("typ", "JWT");
        header.put("alg", key.alg());
        header.put("kid", key.id());

        JWTCredential c = new JWTCredential();
        c.signingInput = encode(header) + "." + encode(payload);
        c.payloadData = new CredentialData(vcMap);
        c.jwtClaims = claims;
        c.signingKey = key;
        c.executeOptions(o);
        return c;
    }

    public static JWTCredential parseJWTCredential(String rawJWT) throws Exception {
        return parseJWTCredential(rawJWT, null);
    }

    public static JWTCredential parseJWTCredential(String rawJWT, CredentialOptions opts) throws Exception {
        String jwt = rawJWT == null ? "" : rawJWT.trim();
        if (jwt.length() >= 2 && jwt.startsWith("\"") && jwt.endsWith("\"")) {
            jwt = jwt.substring(1, jwt.length() - 1).trim();
        }
        // base64url has no "~", so a valid JWT never contains one: a "~" means the SD-JWT combined form.
        if (jwt.contains("~")) {
            throw new SDJWTRequiresJOSEException("parseJWTCredential: token is in SD-JWT combined form");
        }
        if (!CredentialParser.isJWTCredential(jwt)) {
            throw new Exception("invalid JWT format");
        }
        String[] parts = jwt.split("\\.");
        Map<String, Object> payloadMap;
        try {
            payloadMap = MAPPER.readValue(Base64.getUrlDecoder().decode(parts[1]),
                    new TypeReference<LinkedHashMap<String, Object>>() {
                    });
        } catch (Exception e) {
            throw new Exception("failed to decode payload: " + e.getMessage(), e);
        }
        // Digests in the signed payload make it an SD-JWT whether or not a disclosure came with it.
        if (CredentialSupport.carriesSDJWT(payloadMap)) {
            throw new SDJWTRequiresJOSEException("parseJWTCredential: payload carries SD-JWT digests");
        }
        Object vcData = payloadMap.get("vc");
        if (vcData == null) {
            throw new Exception("vc claim not found in JWT payload");
        }
        if (!(vcData instanceof Map)) {
            throw new Exception("vc claim is not a valid JSON object");
        }

        JWTCredential c = new JWTCredential();
        c.signingInput = parts[0] + "." + parts[1];
        c.payloadData = new CredentialData(CredentialSupport.asMap(vcData));
        c.jwtClaims = payloadMap;
        c.signature = parts.length == 3 ? parts[2] : "";
        c.executeOptions(CredentialOptions.orEmpty(opts));
        return c;
    }

    /** Signs with a raw secp256k1 key (hex), like Go {@code NewDefaultProvider}. Prefer a provider. */
    @Override
    public void addProof(String privKeyHex, CredentialOptions opts) throws Exception {
        addProofByProvider(new DefaultSignerProvider(privKeyHex), opts);
    }

    @Override
    public void addProofByProvider(SignerProvider signerProvider, CredentialOptions opts) throws Exception {
        if (signerProvider == null) {
            throw new IllegalArgumentException("signer provider cannot be null");
        }
        CredentialOptions o = CredentialOptions.orEmpty(opts);
        CredentialSupport.rejectBuildTimeOptions(o);
        CredentialSupport.refuseOverwrite(signature, o);
        executeOptions(o.forSigning());

        byte[] digest = MessageDigest.getInstance("SHA-256").digest(signingInput.getBytes(StandardCharsets.UTF_8));
        byte[] raw = signerProvider.sign(digest);
        // Assigned only after Accept succeeds, so a failed call cannot clear a signature the credential had.
        this.signature = signingKey.accept(signingInput, raw);
    }

    @Override
    public byte[] getSigningInput() {
        return signingInput.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Attaches a signature made outside the SDK over {@link #getSigningInput()}: 64-byte r||s (65 with a trailing
     * recovery id is trimmed) that verifies against the VM the header names.
     */
    @Override
    public void addCustomProof(Proof proof, CredentialOptions opts) throws Exception {
        if (proof == null) {
            throw new IllegalArgumentException("proof cannot be null");
        }
        if (proof.getSignature() == null || proof.getSignature().length == 0) {
            throw new Exception("proof signature cannot be empty");
        }
        CredentialOptions o = CredentialOptions.orEmpty(opts);
        CredentialSupport.rejectBuildTimeOptions(o);
        CredentialSupport.refuseOverwrite(signature, o);
        executeOptions(o.forSigning());
        this.signature = signingKey.accept(signingInput, proof.getSignature());
    }

    @Override
    public void verify(CredentialOptions opts) throws Exception {
        CredentialOptions o = CredentialOptions.orEmpty(opts).copy();
        o.setVerifyProof(true);
        executeOptions(o);
    }

    @Override
    public Object serialize() {
        return signature == null || signature.isEmpty() ? signingInput : signingInput + "." + signature;
    }

    @Override
    public String hash() throws Exception {
        if (signature == null || signature.isEmpty()) {
            throw new Exception("credential must be signed before hashing");
        }
        byte[] d = MessageDigest.getInstance("SHA-256")
                .digest(((String) serialize()).getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(d);
    }

    @Override
    public byte[] getContents() throws Exception {
        return ((JSONMap) payloadData).toJSON();
    }

    @Override
    public String getType() {
        return "JWT";
    }

    @Override
    public Object extractField(String path) {
        return Vcdm.extractField(payloadData, path);
    }

    /** A VC 1.1 JWT carries no disclosures; always empty (kept so callers asking every credential keep working). */
    @Deprecated
    public List<DecodedDisclosure> decodedDisclosures() {
        return List.of();
    }

    /** Always refused: a VC 1.1 JWT carries no disclosures to choose from. */
    @Deprecated
    public Credential present(List<String> selectedDisclosures) throws Exception {
        throw new SDJWTRequiresJOSEException("present");
    }

    public CredentialData getPayloadData() {
        return payloadData;
    }

    private void executeOptions(CredentialOptions o) throws Exception {
        CredentialSupport.runContentChecks(payloadData, o);
        if (o.isVerifyProof()) {
            if (signature == null || signature.isEmpty()) {
                throw new Exception("credential verification failed: credential is not signed");
            }
            try {
                new JWTVerifier(o.effectiveResolver()).verifyJWT(signingInput + "." + signature);
            } catch (Exception e) {
                throw new CredentialException(CredentialException.Code.INVALID_PROOF,
                        "credential verification failed: verify proof: " + e.getMessage(), e);
            }
        }
        if (o.isCheckExpiration()) {
            // validFrom/validUntil describe the credential (inside vc); exp/nbf describe the token (beside it).
            // The credential's own window is reported first.
            try {
                CredentialSupport.checkExpiration(payloadData, o.getClockSkewLeewayMs());
                Vcdm.checkTimeClaims(jwtClaims, o.getClockSkewLeewayMs());
            } catch (CredentialException e) {
                throw e;
            } catch (Exception e) {
                throw new Exception("failed to check expiration: " + e.getMessage(), e);
            }
        }
    }

    private static String encode(Object value) throws Exception {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(MAPPER.writeValueAsBytes(value));
    }
}
