package com.pila.credential.vp;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.dto.Proof;
import com.pila.credential.common.error.CredentialException;
import com.pila.credential.common.jwt.JWTVerifier;
import com.pila.credential.common.jwt.SigningKey;
import com.pila.credential.common.signer.DefaultSignerProvider;
import com.pila.credential.common.signer.SignerProvider;
import com.pila.credential.common.util.Vcdm;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * JWT verifiable presentation (VC 1.1 style {@code vp} claim), aligned with Go {@code JWTPresentation}.
 */
public final class JWTPresentation implements Presentation {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private String signingInput;
    private PresentationData payloadData;
    private String signature = "";
    private Map<String, Object> jwtClaims = new LinkedHashMap<>();
    private SigningKey signingKey = SigningKey.NONE;

    private JWTPresentation() {
    }

    public static JWTPresentation create(PresentationContents vpc, PresentationOptions opts) throws Exception {
        PresentationOptions o = PresentationOptions.orEmpty(opts);
        PresentationData m = PresentationHelper.serializePresentationContents(vpc);
        Map<String, Object> claims = new LinkedHashMap<>();
        if (vpc.getHolder() != null && !vpc.getHolder().isEmpty()) {
            claims.put("iss", vpc.getHolder());
            claims.put("sub", vpc.getHolder());
        }
        if (vpc.getValidUntil() != null) {
            claims.put("exp", vpc.getValidUntil().getEpochSecond());
        }
        if (vpc.getValidFrom() != null) {
            long iat = vpc.getValidFrom().getEpochSecond();
            claims.put("iat", iat);
            claims.put("nbf", iat);
        }
        if (vpc.getId() != null && !vpc.getId().isEmpty()) {
            claims.put("jti", vpc.getId());
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("vp", m);
        payload.putAll(claims);
        // challenge/domain map to the standard JWT claims nonce and aud, written only when non-empty.
        if (nonEmpty(o.getChallenge())) {
            payload.put("nonce", o.getChallenge());
        }
        if (nonEmpty(o.getDomain())) {
            payload.put("aud", o.getDomain());
        }

        // Resolve the VM through this call's resolver so alg reflects the key it holds and a kid that is missing or
        // not granted authentication is caught here.
        SigningKey key = SigningKey.resolve(vpc.getHolder(), "authentication", o.getVerificationMethodKey(),
                o.effectiveResolver());
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("typ", "JWT");
        header.put("alg", key.alg());
        header.put("kid", key.id());

        JWTPresentation pres = new JWTPresentation();
        pres.signingInput = base64Url(MAPPER.writeValueAsBytes(header)) + "."
                + base64Url(MAPPER.writeValueAsBytes(payload));
        pres.payloadData = m;
        pres.jwtClaims = payload;
        pres.signingKey = key;
        pres.executeOptions(o);
        return pres;
    }

    public static JWTPresentation newJWTPresentation(PresentationContents vpc, PresentationOptions opts)
            throws Exception {
        return create(vpc, opts);
    }

    public static JWTPresentation parseJWTPresentation(String rawJwt, PresentationOptions opts) throws Exception {
        return parse(rawJwt, opts);
    }

    public static JWTPresentation parse(String rawJwt) throws Exception {
        return parse(rawJwt, null);
    }

    public static JWTPresentation parse(String rawJwt, PresentationOptions opts) throws Exception {
        String trimmed = rawJwt == null ? "" : rawJwt.trim();
        if (trimmed.length() >= 2 && trimmed.startsWith("\"") && trimmed.endsWith("\"")) {
            trimmed = trimmed.substring(1, trimmed.length() - 1);
        }
        if (!PresentationParser.isJWTShaped(trimmed)) {
            throw new Exception("invalid JWT format");
        }
        String[] parts = trimmed.split("\\.");
        Map<String, Object> payload;
        try {
            payload = MAPPER.readValue(Base64.getUrlDecoder().decode(parts[1]),
                    new TypeReference<LinkedHashMap<String, Object>>() {
                    });
        } catch (Exception e) {
            throw new Exception("failed to decode payload: " + e.getMessage(), e);
        }
        Object vpObj = payload.get("vp");
        if (vpObj == null) {
            throw new Exception("vp claim not found in JWT payload");
        }
        if (!(vpObj instanceof Map)) {
            throw new Exception("vp claim is not a valid JSON object");
        }
        JWTPresentation pres = new JWTPresentation();
        pres.signingInput = parts[0] + "." + parts[1];
        pres.payloadData = new PresentationData(PresentationValidation.asMap(vpObj));
        pres.jwtClaims = payload;
        pres.signature = parts.length == 3 ? parts[2] : "";
        pres.executeOptions(PresentationOptions.orEmpty(opts));
        return pres;
    }

    /** Signs with a raw secp256k1 key (hex), like Go {@code NewDefaultProvider}. Prefer a provider. */
    public void addProof(String privKeyHex) throws Exception {
        addProof(privKeyHex, null);
    }

    public void addProof(String privKeyHex, PresentationOptions opts) throws Exception {
        addProofByProvider(new DefaultSignerProvider(privKeyHex), opts);
    }

    public void addProofByProvider(SignerProvider signerProvider) throws Exception {
        addProofByProvider(signerProvider, null);
    }

    /**
     * Signs the token. {@code withChallenge} / {@code withDomain} may be given here: they overwrite nonce/aud and
     * are committed together with the signature, so a failed call leaves the presentation as it was.
     */
    public void addProofByProvider(SignerProvider signerProvider, PresentationOptions opts) throws Exception {
        if (signerProvider == null) {
            throw new IllegalArgumentException("signer provider cannot be null");
        }
        PresentationOptions o = PresentationOptions.orEmpty(opts);
        rejectBuildTimeOptions(o, false);
        PresentationValidation.refuseOverwrite(signature, o);

        Pending pending = pendingChallengeDomain(o);
        executeOptions(o.forSigning());

        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(pending.signingInput.getBytes(StandardCharsets.UTF_8));
        byte[] raw = signerProvider.sign(digest);
        String sig = signingKey.accept(pending.signingInput, raw);
        this.jwtClaims = pending.claims;
        this.signingInput = pending.signingInput;
        this.signature = sig;
    }

    public byte[] getSigningInput() {
        return signingInput.getBytes(StandardCharsets.UTF_8);
    }

    public void addCustomProof(Proof proof) throws Exception {
        addCustomProof(proof, null);
    }

    /**
     * Attaches a signature made outside the SDK over {@link #getSigningInput()}: 64-byte r||s (a trailing recovery id
     * is trimmed) that verifies against the VM the header names. nonce/aud cannot be applied here.
     */
    public void addCustomProof(Proof proof, PresentationOptions opts) throws Exception {
        if (proof == null) {
            throw new IllegalArgumentException("proof cannot be null");
        }
        if (proof.getSignature() == null || proof.getSignature().length == 0) {
            throw new Exception("proof signature cannot be empty");
        }
        PresentationOptions o = PresentationOptions.orEmpty(opts);
        rejectBuildTimeOptions(o, true);
        PresentationValidation.refuseOverwrite(signature, o);
        executeOptions(o.forSigning());
        this.signature = signingKey.accept(signingInput, proof.getSignature());
    }

    @Override
    public void verify(PresentationOptions opts) throws Exception {
        PresentationOptions o = PresentationOptions.orEmpty(opts).copy();
        o.setVerifyProof(true);
        executeOptions(o);
    }

    @Override
    public String serialize() {
        if (signature == null || signature.isEmpty()) {
            return signingInput;
        }
        return signingInput + "." + signature;
    }

    @Override
    public byte[] getContents() throws Exception {
        return payloadData.toJSON();
    }

    @Override
    public String getType() {
        return "JWT";
    }

    @Override
    public Object extractField(String path) {
        return Vcdm.extractField(payloadData, path);
    }

    private void executeOptions(PresentationOptions o) throws Exception {
        if (o.isValidateVC()) {
            PresentationHelper.verifyEmbeddedCredentials(payloadData, o);
        }
        if (o.isCheckExpiration()) {
            // validFrom/validUntil describe the presentation (inside vp); exp/nbf describe the token (beside it).
            try {
                PresentationHelper.checkExpiration(payloadData, o.getClockSkewLeewayMs());
                Vcdm.checkTimeClaims(jwtClaims, o.getClockSkewLeewayMs());
            } catch (CredentialException e) {
                throw e;
            } catch (Exception e) {
                throw new Exception("failed to check expiration: " + e.getMessage(), e);
            }
        }
        if (o.isVerifyProof()) {
            if (signature == null || signature.isEmpty()) {
                throw new Exception("presentation is not signed");
            }
            try {
                new JWTVerifier(o.effectiveResolver()).verifyJWT(signingInput + "." + signature);
            } catch (Exception e) {
                throw new CredentialException(CredentialException.Code.INVALID_PROOF,
                        "failed to verify presentation: " + e.getMessage(), e);
            }
            PresentationAudience.checkChallenge(jwtClaims.get("nonce"), o.getExpectedChallenge());
            PresentationAudience.checkAudience(jwtClaims.get("aud"), o);
        }
    }

    private record Pending(Map<String, Object> claims, String signingInput) {
    }

    // Claims and signing input this call's challenge/domain would produce, WITHOUT writing them into this object.
    private Pending pendingChallengeDomain(PresentationOptions o) throws Exception {
        if (!nonEmpty(o.getChallenge()) && !nonEmpty(o.getDomain())) {
            return new Pending(jwtClaims, signingInput);
        }
        Map<String, Object> claims = new LinkedHashMap<>(jwtClaims);
        if (nonEmpty(o.getChallenge())) {
            claims.put("nonce", o.getChallenge());
        }
        if (nonEmpty(o.getDomain())) {
            claims.put("aud", o.getDomain());
        }
        String header = signingInput.substring(0, signingInput.indexOf('.'));
        return new Pending(claims, header + "." + base64Url(MAPPER.writeValueAsBytes(claims)));
    }

    private static void rejectBuildTimeOptions(PresentationOptions o, boolean signedOutside) throws Exception {
        if (nonEmpty(o.getVerificationMethodKey())) {
            throw new CredentialException(CredentialException.Code.UNSUPPORTED_OPTION,
                    "withVerificationMethodKey cannot be applied when signing a JWT: the header's kid was fixed when "
                            + "the token was built — pass the option to JWTPresentation.create");
        }
        if (signedOutside && (nonEmpty(o.getChallenge()) || nonEmpty(o.getDomain()))) {
            throw new CredentialException(CredentialException.Code.UNSUPPORTED_OPTION,
                    "withChallenge / withDomain cannot be applied by addCustomProof: the signature already covers the "
                            + "signing input — pass them to JWTPresentation.create before getSigningInput, or sign "
                            + "with addProofByProvider");
        }
    }

    private static boolean nonEmpty(String s) {
        return s != null && !s.isEmpty();
    }

    private static String base64Url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }
}
