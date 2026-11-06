package com.pila.credential.vc;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.dto.Proof;
import com.pila.credential.common.error.CredentialException;
import com.pila.credential.common.jwt.JWTVerifier;
import com.pila.credential.common.jwt.SigningKey;
import com.pila.credential.common.sdjwt.DecodedDisclosure;
import com.pila.credential.common.util.Vcdm;
import java.security.MessageDigest;
import com.pila.credential.common.sdjwt.BuildDisclosuresInput;
import com.pila.credential.common.sdjwt.ParsedSDJWT;
import com.pila.credential.common.sdjwt.SDJWT;
import com.pila.credential.common.sdjwt.SDJWTDisclosure;
import com.pila.credential.common.sdjwt.SDJWTReconstruct;
import com.pila.credential.common.sdjwt.SDJWTResult;
import com.pila.credential.common.signer.DefaultSignerProvider;
import com.pila.credential.common.signer.SignerProvider;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * VC-JOSE credential (vc+jwt / vc+sd-jwt) with flat JWS payload (no nested {@code vc} claim).
 */
public class JOSECredential implements SignableCredential {

    public static final String TYPE_VC_JWT = "vc+jwt";
    public static final String TYPE_VC_SD_JWT = "vc+sd-jwt";
    private static final String CREDENTIALS_V2_CONTEXT = "https://www.w3.org/ns/credentials/v2";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private String signingInput;
    private CredentialData payloadData;
    private String signature;
    private List<String> disclosures;
    private boolean disclosable; // payload carries _sd digests, even if this holder reveals none
    private SigningKey signingKey = SigningKey.NONE; // VM the header names; NONE for a parsed credential

    private JOSECredential() {
        this.disclosures = new ArrayList<>();
    }

    public static boolean isJOSECredentialTyp(String typ) {
        if (typ == null || typ.isEmpty()) {
            return false;
        }
        return TYPE_VC_JWT.equals(typ)
                || ("application/" + TYPE_VC_JWT).equals(typ)
                || TYPE_VC_SD_JWT.equals(typ)
                || ("application/" + TYPE_VC_SD_JWT).equals(typ);
    }

    public static String peekJwtTyp(String token) {
        String base = token.contains("~") ? token.split("~", 2)[0] : token;
        String[] parts = base.split("\\.");
        if (parts.length < 2) {
            return null;
        }
        try {
            byte[] headerBytes = Base64.getUrlDecoder().decode(parts[0]);
            Map<String, Object> header = MAPPER.readValue(headerBytes, new TypeReference<Map<String, Object>>() {
            });
            Object typ = header.get("typ");
            return typ instanceof String s ? s : null;
        } catch (Exception e) {
            return null;
        }
    }

    /** Go-style names: {@code newJOSECredential} / {@code parseJOSECredential}. */
    public static JOSECredential newJOSECredential(CredentialContents vcc, CredentialOptions opts) throws Exception {
        return create(vcc, opts);
    }

    public static JOSECredential parseJOSECredential(String rawJWT, CredentialOptions opts) throws Exception {
        return parse(rawJWT, opts);
    }

    public static JOSECredential create(CredentialContents vcc) throws Exception {
        return create(vcc, new CredentialOptions());
    }

    public static JOSECredential create(CredentialContents vcc, CredentialOptions opts) throws Exception {
        CredentialOptions o = CredentialOptions.orEmpty(opts);
        if (vcc == null) {
            throw new IllegalArgumentException("credential contents is nil");
        }
        vcc = copyContents(vcc);
        vcc.setContext(requireV2Context(vcc.getContext()));
        if (vcc.getTypes() == null || vcc.getTypes().isEmpty()) {
            vcc.setTypes(List.of("VerifiableCredential"));
        }

        CredentialData m = CredentialHelper.serializeCredentialContents(vcc);
        Map<String, Object> vcMap = new HashMap<>(m);
        // The same check parse runs, so the two ends cannot disagree about what a vc+jwt is.
        CredentialSupport.requireJOSECredential(vcMap);

        BuildDisclosuresInput input = new BuildDisclosuresInput();
        input.vc = vcMap;
        input.selectivePaths = o.getSdSelectivePaths();
        input.hashAlgorithm = o.getSdAlg() == null || o.getSdAlg().isEmpty() ? null : o.getSdAlg();
        input.shuffle = o.isSdShuffle();
        input.decoys = o.getSdDecoys();
        SDJWTResult result = SDJWTDisclosure.buildDisclosures(input);
        vcMap = result.processedVC;
        List<String> disclosures = new ArrayList<>(result.disclosures);
        if (o.getSdDisclosures() != null) {
            disclosures.addAll(o.getSdDisclosures());
        }
        // _sd_alg marks the payload as selectively disclosed, so it must be written for prebuilt disclosures too
        // (sha-256 by default, RFC 9901 4.1.1); otherwise the typ stays vc+jwt and the digests leak on re-parse.
        if (o.getSdDisclosures() != null && !o.getSdDisclosures().isEmpty() && !vcMap.containsKey("_sd_alg")) {
            vcMap.put("_sd_alg", o.getSdAlg() == null || o.getSdAlg().isEmpty()
                    ? SDJWT.DEFAULT_HASH_ALGORITHM : o.getSdAlg());
        }
        // Nothing outside credentialSubject may be disclosable; the subject itself is exempt.
        CredentialSupport.requireDisclosableAtTopLevel(vcMap, true);
        // Reconstruct deep-copies, so this validates (7.1 rules: no unmatched, duplicate or twice-referenced
        // disclosure) without touching what gets signed.
        try {
            SDJWTReconstruct.reconstruct(vcMap, disclosures, true);
        } catch (Exception e) {
            throw new Exception("invalid SD-JWT disclosures: " + e.getMessage(), e);
        }
        boolean disclosable = vcMap.containsKey("_sd_alg");

        vcMap.remove("vc");
        vcMap.remove("vp");
        // Without iat the verifier has no signing time to compare a soft revocation against.
        vcMap.put("iat", java.time.Instant.now().getEpochSecond());

        // Resolve the VM the header will name and keep it: every signing path checks the signature it is handed
        // against this key, so a signature by another key fails here rather than at the receiver.
        SigningKey key = SigningKey.resolve(vcc.getIssuer(), "assertionMethod", o.getVerificationMethodKey(),
                o.effectiveResolver());
        Map<String, Object> header = new java.util.LinkedHashMap<>();
        header.put("typ", disclosable ? TYPE_VC_SD_JWT : TYPE_VC_JWT);
        header.put("alg", key.alg());
        header.put("kid", key.id());

        JOSECredential cred = new JOSECredential();
        cred.signingInput = encodeJson(header) + "." + encodeJson(vcMap);
        cred.payloadData = new CredentialData(vcMap);
        cred.disclosures = disclosures;
        cred.disclosable = disclosable;
        cred.signingKey = key;
        cred.executeOptions(o);
        return cred;
    }

    public static JOSECredential parse(String rawJWT) throws Exception {
        return parse(rawJWT, null);
    }

    public static JOSECredential parse(String rawJWT, CredentialOptions opts) throws Exception {
        String trimmed = rawJWT.trim();
        if (trimmed.length() >= 2 && trimmed.startsWith("\"") && trimmed.endsWith("\"")) {
            trimmed = trimmed.substring(1, trimmed.length() - 1).trim();
        }

        String issuerJWT;
        List<String> disclosures = new ArrayList<>();
        boolean combinedSD = SDJWT.isSDJWT(trimmed);
        if (combinedSD) {
            ParsedSDJWT parsed;
            try {
                parsed = SDJWT.parse(trimmed);
            } catch (Exception e) {
                throw new Exception("failed to parse SD-JWT: " + e.getMessage(), e);
            }
            issuerJWT = parsed.baseJWT;
            disclosures = new ArrayList<>(parsed.disclosures);
        } else {
            if (!CredentialParser.isJWTCredential(trimmed)) {
                throw new Exception("invalid JWT or SD-JWT format");
            }
            issuerJWT = trimmed;
        }

        String[] parts = issuerJWT.split("\\.");
        Map<String, Object> headerMap = decodeJson(parts[0]);
        String typ = headerMap.get("typ") instanceof String s ? s : null;
        if (!isJOSECredentialTyp(typ)) {
            throw new Exception("invalid typ header for JOSECredential: got \"" + typ + "\", want \""
                    + TYPE_VC_JWT + "\" or \"" + TYPE_VC_SD_JWT + "\"");
        }

        Map<String, Object> payloadMap = decodeJson(parts[1]);
        if (payloadMap.containsKey("vc") || payloadMap.containsKey("vp")) {
            throw new Exception("invalid vc-jose-cose: 'vc' or 'vp' claim MUST NOT be present in payload");
        }

        // The media type and the combined format say how the token was secured; _sd_alg is only a third signal
        // (it is optional in RFC 9901).
        boolean hasSDAlg = payloadMap.containsKey("_sd_alg");
        boolean declaredSD = TYPE_VC_SD_JWT.equals(typ.replaceFirst("^application/", ""));
        if (!declaredSD && (combinedSD || hasSDAlg)) {
            throw new Exception("typ \"" + typ + "\" does not match the SD-JWT format");
        }
        // Whatever the holder sent, the issuer must not have made anything outside credentialSubject disclosable:
        // a withheld disclosure leaves only a digest. Runs before reconstruct, which removes the evidence.
        CredentialSupport.requireDisclosableAtTopLevel(payloadMap, declaredSD);

        Map<String, Object> vcMap = payloadMap;
        boolean disclosable = declaredSD || combinedSD || hasSDAlg;
        if (disclosable || !disclosures.isEmpty()) {
            try {
                vcMap = SDJWTReconstruct.reconstruct(vcMap, disclosures, true);
            } catch (Exception e) {
                throw new Exception("failed to reconstruct SD-JWT payload: " + e.getMessage(), e);
            }
        }
        try {
            CredentialSupport.requireSecuredClaimsSigned(payloadMap, vcMap);
        } catch (Exception e) {
            throw new Exception("invalid " + typ + " payload: " + e.getMessage(), e);
        }
        // A signature proves who produced the bytes, not that the bytes are a credential.
        CredentialSupport.requireJOSECredential(vcMap);

        JOSECredential cred = new JOSECredential();
        cred.signingInput = parts[0] + "." + parts[1];
        cred.payloadData = new CredentialData(vcMap);
        cred.signature = parts.length == 3 ? parts[2] : "";
        cred.disclosures = disclosures;
        cred.disclosable = disclosable;
        cred.executeOptions(CredentialOptions.orEmpty(opts));
        return cred;
    }

    /** Signs with a raw secp256k1 key (hex). Prefer a provider. */
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
        // Accept trims a recovery id, checks the r||s shape and verifies against the key the header names; the
        // signature is assigned only after all of that, so a failed call needs no rollback.
        this.signature = signingKey.accept(signingInput, raw);
    }

    @Override
    public byte[] getSigningInput() {
        return signingInput.getBytes(StandardCharsets.UTF_8);
    }

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

    /**
     * The token to hand to someone else: the issuer-signed JWT and, for an SD-JWT, the disclosures this holder
     * reveals each after a "~", terminated by "~". Unsigned: {@code header.payload~d~}.
     */
    @Override
    public Object serialize() {
        String base = signature != null && !signature.isEmpty() ? signingInput + "." + signature : signingInput;
        if (!disclosable) {
            return base;
        }
        StringBuilder out = new StringBuilder(base);
        for (String d : disclosures) {
            if (d == null || d.isEmpty()) {
                continue;
            }
            out.append('~').append(d);
        }
        return out.append('~').toString();
    }

    @Override
    public byte[] getContents() throws Exception {
        return MAPPER.writeValueAsBytes(payloadData);
    }

    @Override
    public String getType() {
        return "JOSE";
    }

    @Override
    public Object extractField(String path) {
        return Vcdm.extractField(payloadData, path);
    }

    public CredentialData getPayloadData() {
        return payloadData;
    }

    public boolean isDisclosable() {
        return disclosable;
    }

    /** Which fields this token still discloses, decoded from the salted arrays that travel after the signature. */
    public List<DecodedDisclosure> decodedDisclosures() throws Exception {
        return SDJWT.decodeDisclosures(disclosures);
    }

    public JOSECredential present(List<String> selectedDisclosures) throws Exception {
        if (signature == null || signature.isEmpty()) {
            throw new Exception("cannot present an unsigned credential");
        }
        if (!disclosable) {
            throw new Exception("credential carries no disclosures; nothing to present selectively");
        }
        return parse(SDJWT.buildSDJWTPresentation(signingInput + "." + signature, selectedDisclosures));
    }

    @Override
    public String hash() throws Exception {
        if (signature == null || signature.isEmpty()) {
            throw new Exception("credential must be signed before hashing");
        }
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(((String) serialize()).getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(digest);
    }

    private void executeOptions(CredentialOptions o) throws Exception {
        CredentialSupport.runContentChecks(payloadData, o);
        if (o.isVerifyProof()) {
            if (signature == null || signature.isEmpty()) {
                throw new Exception("credential verification failed: credential is not signed");
            }
            try {
                // The issuer-signed JWT only: disclosures are outside the signature.
                new JWTVerifier(o.effectiveResolver()).verifyJWT(signingInput + "." + signature);
                // exp and nbf bound the signature, not the credential, so they belong to every verification.
                Vcdm.checkTimeClaims(payloadData, o.getClockSkewLeewayMs());
            } catch (Exception e) {
                throw new CredentialException(CredentialException.Code.INVALID_PROOF,
                        "credential verification failed: verify proof: " + e.getMessage(), e);
            }
        }
        if (o.isCheckExpiration()) {
            try {
                CredentialSupport.checkExpiration(payloadData, o.getClockSkewLeewayMs());
            } catch (CredentialException e) {
                throw e;
            } catch (Exception e) {
                throw new Exception("failed to check expiration: " + e.getMessage(), e);
            }
        }
    }

    private static List<Object> requireV2Context(List<Object> context) throws Exception {
        if (context == null || context.isEmpty()) {
            return List.of(CREDENTIALS_V2_CONTEXT);
        }
        Object first = context.get(0);
        if (!CREDENTIALS_V2_CONTEXT.equals(first)) {
            throw new Exception("credential must name \"" + CREDENTIALS_V2_CONTEXT
                    + "\" first in @context, got " + MAPPER.writeValueAsString(first));
        }
        return context;
    }

    private static CredentialContents copyContents(CredentialContents vcc) {
        CredentialContents copy = new CredentialContents();
        copy.setContext(vcc.getContext() != null ? new ArrayList<>(vcc.getContext()) : null);
        copy.setId(vcc.getId());
        copy.setTypes(vcc.getTypes() != null ? new ArrayList<>(vcc.getTypes()) : null);
        copy.setIssuer(vcc.getIssuer());
        copy.setValidFrom(vcc.getValidFrom());
        copy.setValidUntil(vcc.getValidUntil());
        copy.setSubject(vcc.getSubject());
        copy.setSchemas(vcc.getSchemas());
        copy.setCredentialStatus(vcc.getCredentialStatus());
        return copy;
    }

    private static String encodeJson(Object value) throws Exception {
        byte[] json = MAPPER.writeValueAsBytes(value);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json);
    }

    private static Map<String, Object> decodeJson(String encoded) throws Exception {
        byte[] bytes = Base64.getUrlDecoder().decode(encoded);
        return MAPPER.readValue(bytes, new TypeReference<Map<String, Object>>() {
        });
    }
}
