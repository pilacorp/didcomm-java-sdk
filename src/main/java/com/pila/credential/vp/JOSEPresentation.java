package com.pila.credential.vp;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.dto.Proof;
import com.pila.credential.common.error.CredentialException;
import com.pila.credential.common.jwt.JWTVerifier;
import com.pila.credential.common.jwt.SigningKey;
import com.pila.credential.common.sdjwt.SDJWT;
import com.pila.credential.common.signer.DefaultSignerProvider;
import com.pila.credential.common.signer.SignerProvider;
import com.pila.credential.common.util.Vcdm;
import com.pila.credential.vc.Credential;
import com.pila.credential.vc.CredentialParser;
import com.pila.credential.vc.JOSECredential;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * W3C VC 2.0 verifiable presentation secured with JOSE (vc-jose-cose): the unsecured presentation is the flat JWS
 * payload (no {@code vp} wrapper claim) and the header carries {@code typ: vp+jwt}. Embedded credentials travel as
 * EnvelopedVerifiableCredential entries.
 */
public final class JOSEPresentation implements Presentation {
    public static final String TYPE_VP_JWT = "vp+jwt";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private String signingInput;
    private PresentationData payloadData;
    private String signature = "";
    private SigningKey signingKey = SigningKey.NONE;

    private JOSEPresentation() {
    }

    public static boolean isJOSEPresentationTyp(String typ) {
        return TYPE_VP_JWT.equals(typ) || ("application/" + TYPE_VP_JWT).equals(typ);
    }

    public static JOSEPresentation create(PresentationContents vpc) throws Exception {
        return create(vpc, null);
    }

    public static JOSEPresentation create(PresentationContents vpc, PresentationOptions opts) throws Exception {
        PresentationOptions o = PresentationOptions.orEmpty(opts);
        if (vpc == null) {
            throw new IllegalArgumentException("presentation contents is nil");
        }
        if (vpc.getContext() == null || vpc.getContext().isEmpty()) {
            PresentationContents copy = copy(vpc);
            copy.setContext(new ArrayList<>(List.of(Vcdm.CONTEXT_V2)));
            vpc = copy;
        }
        PresentationData payload = PresentationHelper.serializePresentationContents(vpc);
        // Refuse before signing what parse would refuse after.
        PresentationValidation.requireJOSEPresentation(payload);

        // Embedded credentials become EnvelopedVerifiableCredential entries; Data Integrity credentials secure the
        // document from the inside, have no media type, and belong in a JSON presentation.
        if (vpc.getVerifiableCredentials() != null && !vpc.getVerifiableCredentials().isEmpty()) {
            List<Object> enveloped = new ArrayList<>();
            for (int i = 0; i < vpc.getVerifiableCredentials().size(); i++) {
                Credential cred = vpc.getVerifiableCredentials().get(i);
                if (!(cred instanceof JOSECredential jose)) {
                    throw new Exception("credential at index " + i + " is "
                            + (cred == null ? "null" : cred.getClass().getSimpleName())
                            + ": a vp+jwt presentation can only carry enveloping-secured credentials; use a JSON "
                            + "presentation for Data Integrity credentials");
                }
                String credStr = (String) jose.serialize();
                String mediaType;
                try {
                    mediaType = envelopeMediaType(credStr);
                } catch (Exception e) {
                    throw new Exception("credential at index " + i + ": " + e.getMessage(), e);
                }
                Map<String, Object> env = new LinkedHashMap<>();
                env.put("@context", List.of(Vcdm.CONTEXT_V2));
                env.put("type", List.of(CredentialParser.TYPE_ENVELOPED_VC));
                env.put("id", "data:application/" + mediaType + "," + credStr);
                enveloped.add(env);
            }
            payload.put("verifiableCredential", enveloped);
        }
        if (nonEmpty(o.getChallenge())) {
            payload.put("nonce", o.getChallenge());
        }
        if (nonEmpty(o.getDomain())) {
            payload.put("aud", o.getDomain());
        }
        payload.remove("vc");
        payload.remove("vp");
        // Without iat a verifier has no signing time to compare a soft revocation against.
        payload.put("iat", Instant.now().getEpochSecond());

        SigningKey key = SigningKey.resolve(vpc.getHolder(), "authentication", o.getVerificationMethodKey(),
                o.effectiveResolver());
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("typ", TYPE_VP_JWT);
        header.put("alg", key.alg());
        header.put("kid", key.id());

        JOSEPresentation pres = new JOSEPresentation();
        pres.signingInput = base64Url(MAPPER.writeValueAsBytes(header)) + "."
                + base64Url(MAPPER.writeValueAsBytes(payload));
        pres.payloadData = payload;
        pres.signingKey = key;
        pres.executeOptions(o);
        return pres;
    }

    public static JOSEPresentation newJOSEPresentation(PresentationContents vpc, PresentationOptions opts)
            throws Exception {
        return create(vpc, opts);
    }

    public static JOSEPresentation parseJOSEPresentation(String rawJwt, PresentationOptions opts) throws Exception {
        return parse(rawJwt, opts);
    }

    public static JOSEPresentation parse(String rawJwt) throws Exception {
        return parse(rawJwt, null);
    }

    public static JOSEPresentation parse(String rawJwt, PresentationOptions opts) throws Exception {
        String trimmed = rawJwt == null ? "" : rawJwt.trim();
        if (trimmed.length() >= 2 && trimmed.startsWith("\"") && trimmed.endsWith("\"")) {
            trimmed = trimmed.substring(1, trimmed.length() - 1).trim();
        }
        if (!PresentationParser.isJWTShaped(trimmed)) {
            throw new Exception("invalid JWT format");
        }
        String[] parts = trimmed.split("\\.");
        Map<String, Object> header = decode(parts[0], "header");
        String typ = header.get("typ") instanceof String s ? s : null;
        if (!isJOSEPresentationTyp(typ)) {
            throw new Exception("invalid typ header for JOSEPresentation: got \"" + typ + "\", want \""
                    + TYPE_VP_JWT + "\"");
        }
        Map<String, Object> payload = decode(parts[1], "payload");
        if (payload.containsKey("vc") || payload.containsKey("vp")) {
            throw new Exception("invalid vc-jose-cose: 'vc' or 'vp' claim MUST NOT be present in payload");
        }
        // Both checks run unconditionally: they decide whether this is a well-formed vp+jwt at all.
        PresentationValidation.requireJOSEPresentation(payload);
        requireEnvelopedCredentials(payload);

        JOSEPresentation pres = new JOSEPresentation();
        pres.signingInput = parts[0] + "." + parts[1];
        pres.payloadData = new PresentationData(payload);
        pres.signature = parts.length == 3 ? parts[2] : "";
        pres.executeOptions(PresentationOptions.orEmpty(opts));
        return pres;
    }

    /** Credentials inside a vp+jwt must be EnvelopedVerifiableCredential (vc-jose-cose 3.1.2), single or array. */
    private static void requireEnvelopedCredentials(Map<String, Object> m) throws Exception {
        Object raw = m.get("verifiableCredential");
        if (raw == null) {
            return;
        }
        List<?> items = raw instanceof List<?> l ? l : List.of(raw);
        for (int i = 0; i < items.size(); i++) {
            if (!(items.get(i) instanceof Map<?, ?> entry)
                    || !Vcdm.hasType(entry.get("type"), CredentialParser.TYPE_ENVELOPED_VC)) {
                throw new Exception("credential at index " + i + " must be an " + CredentialParser.TYPE_ENVELOPED_VC
                        + "; a " + TYPE_VP_JWT + " carries credentials enveloped, not bare");
            }
        }
    }

    /** vc+sd-jwt when the token has disclosures, else vc+jwt; an unsigned token is refused. */
    private static String envelopeMediaType(String token) throws Exception {
        String base = token.contains("~") ? token.substring(0, token.indexOf('~')) : token;
        String[] parts = base.split("\\.", -1);
        if (parts.length != 3 || parts[2].isEmpty()) {
            throw new Exception("credential is not signed; sign it before putting it in a presentation");
        }
        return SDJWT.isSDJWT(token) ? JOSECredential.TYPE_VC_SD_JWT : JOSECredential.TYPE_VC_JWT;
    }

    /** Signs with a raw secp256k1 key (hex). Prefer a provider. */
    public void addProof(String privKeyHex, PresentationOptions opts) throws Exception {
        addProofByProvider(new DefaultSignerProvider(privKeyHex), opts);
    }

    public void addProofByProvider(SignerProvider signerProvider) throws Exception {
        addProofByProvider(signerProvider, null);
    }

    public void addProofByProvider(SignerProvider signerProvider, PresentationOptions opts) throws Exception {
        if (signerProvider == null) {
            throw new IllegalArgumentException("signer provider cannot be null");
        }
        PresentationOptions o = PresentationOptions.orEmpty(opts);
        rejectBuildTimeOptions(o, false);
        PresentationValidation.refuseOverwrite(signature, o);

        PresentationData payload = payloadData;
        String input = signingInput;
        if (nonEmpty(o.getChallenge()) || nonEmpty(o.getDomain())) {
            payload = new PresentationData(payloadData);
            if (nonEmpty(o.getChallenge())) {
                payload.put("nonce", o.getChallenge());
            }
            if (nonEmpty(o.getDomain())) {
                payload.put("aud", o.getDomain());
            }
            input = signingInput.substring(0, signingInput.indexOf('.')) + "."
                    + base64Url(MAPPER.writeValueAsBytes(payload));
        }
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(input.getBytes(StandardCharsets.UTF_8));
        String sig = signingKey.accept(input, signerProvider.sign(digest));

        // Commit only once there is a signature, and undo it if the options reject what was produced.
        PresentationData prevPayload = payloadData;
        String prevInput = signingInput;
        String prevSignature = signature;
        payloadData = payload;
        signingInput = input;
        signature = sig;
        try {
            executeOptions(o.forSigning());
        } catch (Exception e) {
            payloadData = prevPayload;
            signingInput = prevInput;
            signature = prevSignature;
            throw e;
        }
    }

    public byte[] getSigningInput() {
        return signingInput.getBytes(StandardCharsets.UTF_8);
    }

    public void addCustomProof(Proof proof) throws Exception {
        addCustomProof(proof, null);
    }

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
        return signature == null || signature.isEmpty() ? signingInput : signingInput + "." + signature;
    }

    public String hash() throws Exception {
        if (signature == null || signature.isEmpty()) {
            throw new Exception("presentation must be signed before hashing");
        }
        return HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(serialize().getBytes(StandardCharsets.UTF_8)));
    }

    @Override
    public byte[] getContents() throws Exception {
        return payloadData.toJSON();
    }

    @Override
    public String getType() {
        return "JOSE";
    }

    @Override
    public Object extractField(String path) {
        return Vcdm.extractField(payloadData, path);
    }

    private void executeOptions(PresentationOptions o) throws Exception {
        if (o.isValidateVC()) {
            PresentationHelper.verifyEmbeddedCredentials(payloadData, o);
        }
        if (o.isVerifyProof()) {
            if (signature == null || signature.isEmpty()) {
                throw new Exception("presentation verification failed: presentation is not signed");
            }
            try {
                new JWTVerifier(o.effectiveResolver()).verifyJWT(signingInput + "." + signature);
                // exp and nbf bound the signature, not the presentation.
                Vcdm.checkTimeClaims(payloadData, o.getClockSkewLeewayMs());
            } catch (Exception e) {
                throw new CredentialException(CredentialException.Code.INVALID_PROOF,
                        "presentation verification failed: verify proof: " + e.getMessage(), e);
            }
            PresentationAudience.checkChallenge(payloadData.get("nonce"), o.getExpectedChallenge());
            PresentationAudience.checkAudience(payloadData.get("aud"), o);
        }
        if (o.isCheckExpiration()) {
            try {
                PresentationHelper.checkExpiration(payloadData, o.getClockSkewLeewayMs());
            } catch (CredentialException e) {
                throw e;
            } catch (Exception e) {
                throw new Exception("failed to check expiration: " + e.getMessage(), e);
            }
        }
    }

    private static void rejectBuildTimeOptions(PresentationOptions o, boolean signedOutside) throws Exception {
        if (nonEmpty(o.getVerificationMethodKey())) {
            throw new CredentialException(CredentialException.Code.UNSUPPORTED_OPTION,
                    "withVerificationMethodKey cannot be applied when signing a JWT: the header's kid was fixed when "
                            + "the token was built — pass the option to JOSEPresentation.create");
        }
        if (signedOutside && (nonEmpty(o.getChallenge()) || nonEmpty(o.getDomain()))) {
            throw new CredentialException(CredentialException.Code.UNSUPPORTED_OPTION,
                    "withChallenge / withDomain cannot be applied by addCustomProof: the signature already covers the "
                            + "signing input — pass them to JOSEPresentation.create before getSigningInput");
        }
    }

    private static PresentationContents copy(PresentationContents v) {
        PresentationContents c = new PresentationContents();
        c.setContext(v.getContext() != null ? new ArrayList<>(v.getContext()) : new ArrayList<>());
        c.setId(v.getId());
        c.setTypes(v.getTypes());
        c.setHolder(v.getHolder());
        c.setValidFrom(v.getValidFrom());
        c.setValidUntil(v.getValidUntil());
        c.setVerifiableCredentials(v.getVerifiableCredentials());
        return c;
    }

    private static Map<String, Object> decode(String b64, String what) throws Exception {
        try {
            return MAPPER.readValue(Base64.getUrlDecoder().decode(b64), new TypeReference<LinkedHashMap<String, Object>>() {
            });
        } catch (Exception e) {
            throw new Exception("failed to decode " + what + ": " + e.getMessage(), e);
        }
    }

    private static boolean nonEmpty(String s) {
        return s != null && !s.isEmpty();
    }

    private static String base64Url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }
}
