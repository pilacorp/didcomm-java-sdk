package com.pila.credential.vp;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.jwt.JWTSigner;
import com.pila.credential.common.jwt.JWTVerifier;
import com.pila.credential.common.signer.DefaultSignerProvider;
import com.pila.credential.common.signer.SignerProvider;
import com.pila.credential.common.verificationmethod.ResolveVmUrl;
import com.pila.credential.vc.CredentialConfig;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * JWT verifiable presentation (VC 1.1 style {@code vp} claim), aligned with Go/TS {@code JWTPresentation}.
 */
public final class JWTPresentation {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private String signingInput;
    private PresentationData payloadData;
    private String signature = "";

    private JWTPresentation(String signingInput, PresentationData payloadData) {
        this.signingInput = signingInput;
        this.payloadData = payloadData;
    }

    public static JWTPresentation create(PresentationContents vpc, PresentationOptions opts) throws Exception {
        PresentationData m = PresentationHelper.serializePresentationContents(vpc);
        Map<String, Object> otherClaims = new HashMap<>();
        if (vpc.getHolder() != null && !vpc.getHolder().isEmpty()) {
            otherClaims.put("iss", vpc.getHolder());
            otherClaims.put("sub", vpc.getHolder());
        }
        if (vpc.getValidUntil() != null) {
            otherClaims.put("exp", vpc.getValidUntil().getEpochSecond());
        }
        if (vpc.getValidFrom() != null) {
            long iat = vpc.getValidFrom().getEpochSecond();
            otherClaims.put("iat", iat);
            otherClaims.put("nbf", iat);
        }
        if (vpc.getId() != null && !vpc.getId().isEmpty()) {
            otherClaims.put("jti", vpc.getId());
        }
        if (opts != null) {
            if (opts.getChallenge() != null) {
                otherClaims.put("nonce", opts.getChallenge());
            }
            if (opts.getDomain() != null) {
                otherClaims.put("aud", opts.getDomain());
            }
        }

        Map<String, Object> payload = new HashMap<>(otherClaims);
        payload.put("vp", m);

        String holder = vpc.getHolder();
        if (holder == null || holder.isEmpty()) {
            throw new Exception("holder is required to resolve VM");
        }
        String vmKey = opts != null && opts.getVerificationMethodKey() != null ? opts.getVerificationMethodKey() : "";
        var signing = ResolveVmUrl.resolveSigningVM(holder, "authentication", vmKey,
                CredentialConfig.getDocumentResolver());
        String kid = signing.url();

        Map<String, Object> header = Map.of("typ", "JWT", "alg", "ES256K", "kid", kid);
        String headerEncoded = base64Url(MAPPER.writeValueAsBytes(header));
        String payloadEncoded = base64Url(MAPPER.writeValueAsBytes(payload));
        return new JWTPresentation(headerEncoded + "." + payloadEncoded, m);
    }

    public void addProofByProvider(SignerProvider signerProvider) throws Exception {
        if (signerProvider == null) {
            throw new IllegalArgumentException("signer provider cannot be null");
        }
        JWTSigner jwtSigner = new JWTSigner(signerProvider);
        this.signature = jwtSigner.signString(signingInput);
    }

    public void addProof(String privKeyHex) throws Exception {
        addProofByProvider(new DefaultSignerProvider(privKeyHex));
    }

    public void verify() throws Exception {
        if (signature == null || signature.isEmpty()) {
            throw new Exception("presentation has no signature");
        }
        String jws = signingInput + "." + signature;
        JWTVerifier verifier = new JWTVerifier(CredentialConfig.getBaseURL());
        verifier.verifyJWT(jws);
    }

    public String serialize() {
        if (signature == null || signature.isEmpty()) {
            return signingInput;
        }
        return signingInput + "." + signature;
    }

    public byte[] getContents() throws Exception {
        return MAPPER.writeValueAsBytes(payloadData);
    }

    public String getType() {
        return "JWT";
    }

    private static String base64Url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    public static JWTPresentation parse(String rawJwt) throws Exception {
        String trimmed = rawJwt.trim();
        String[] parts = trimmed.split("\\.");
        if (parts.length < 2) {
            throw new Exception("invalid JWT presentation");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> payload = MAPPER.readValue(Base64.getUrlDecoder().decode(parts[1]), Map.class);
        Object vpObj = payload.get("vp");
        if (!(vpObj instanceof Map)) {
            throw new Exception("JWT presentation payload missing vp");
        }
        PresentationData data = MAPPER.convertValue(vpObj, PresentationData.class);
        JWTPresentation pres = new JWTPresentation(parts[0] + "." + parts[1], data);
        if (parts.length == 3) {
            pres.signature = parts[2];
        }
        return pres;
    }
}
