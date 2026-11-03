package com.pila.credential.vc;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.dto.Proof;
import com.pila.credential.common.jwt.JWTSigner;
import com.pila.credential.common.jwt.JWTVerifier;
import com.pila.credential.common.sdjwt.BuildDisclosuresInput;
import com.pila.credential.common.sdjwt.ParsedSDJWT;
import com.pila.credential.common.sdjwt.SDJWT;
import com.pila.credential.common.sdjwt.SDJWTDisclosure;
import com.pila.credential.common.sdjwt.SDJWTReconstruct;
import com.pila.credential.common.sdjwt.SDJWTResult;
import com.pila.credential.common.signer.DefaultSignerProvider;
import com.pila.credential.common.signer.SignerProvider;
import com.pila.credential.common.verificationmethod.ResolveVmUrl;

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
public class JOSECredential implements Credential {

    public static final String TYPE_VC_JWT = "vc+jwt";
    public static final String TYPE_VC_SD_JWT = "vc+sd-jwt";
    private static final String CREDENTIALS_V2_CONTEXT = "https://www.w3.org/ns/credentials/v2";
    private static final String DEFAULT_VERIFICATION_METHOD_KEY = "key-1";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private String signingInput;
    private CredentialData payloadData;
    private String signature;
    private List<String> disclosures;
    private String verificationMethodKey;

    private JOSECredential() {
        this.disclosures = new ArrayList<>();
        this.verificationMethodKey = DEFAULT_VERIFICATION_METHOD_KEY;
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

    public static JOSECredential create(CredentialContents vcc) throws Exception {
        return create(vcc, new CredentialOptions());
    }

    public static JOSECredential create(CredentialContents vcc, CredentialOptions opts) throws Exception {
        if (opts == null) {
            opts = new CredentialOptions();
        }
        List<String> sdSelectivePaths = opts.getSdSelectivePaths();
        String sdAlg = opts.getSdAlg() == null || opts.getSdAlg().isEmpty() ? null : opts.getSdAlg();
        Boolean sdShuffle = opts.isSdShuffle();
        List<BuildDisclosuresInput.DecoyConfig> sdDecoys = opts.getSdDecoys();
        List<String> sdDisclosures = opts.getSdDisclosures();
        String verificationMethodKey = opts.getVerificationMethodKey();
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
        requireJOSECredential(vcMap);

        BuildDisclosuresInput input = new BuildDisclosuresInput();
        input.vc = vcMap;
        input.selectivePaths = sdSelectivePaths;
        input.hashAlgorithm = sdAlg;
        input.shuffle = sdShuffle;
        input.decoys = sdDecoys;
        SDJWTResult result = SDJWTDisclosure.buildDisclosures(input);
        vcMap = result.processedVC;
        List<String> disclosures = new ArrayList<>(result.disclosures);
        if (sdDisclosures != null) {
            disclosures.addAll(sdDisclosures);
        }
        vcMap.remove("vc");
        vcMap.remove("vp");

        if (vcc.getIssuer() == null || vcc.getIssuer().isEmpty()) {
            throw new Exception("issuer is required to resolve VM");
        }
        String vmKey = verificationMethodKey != null && !verificationMethodKey.isEmpty()
                ? verificationMethodKey
                : DEFAULT_VERIFICATION_METHOD_KEY;
        var resolver = opts.getResolver() != null
                ? opts.getResolver()
                : (opts.getDidBaseURL() != null && !opts.getDidBaseURL().isEmpty()
                        ? CredentialConfig.resolverFor(opts.getDidBaseURL())
                        : CredentialConfig.getDocumentResolver());
        var signing = ResolveVmUrl.resolveSigningVM(
                vcc.getIssuer(), "assertionMethod", vmKey, resolver);

        boolean disclosable = vcMap.containsKey("_sd_alg");
        Map<String, Object> header = new HashMap<>();
        header.put("typ", disclosable || !disclosures.isEmpty() ? TYPE_VC_SD_JWT : TYPE_VC_JWT);
        header.put("alg", "ES256K");
        header.put("kid", signing.url());

        String headerEncoded = encodeJson(header);
        String payloadEncoded = encodeJson(vcMap);

        JOSECredential cred = new JOSECredential();
        cred.signingInput = headerEncoded + "." + payloadEncoded;
        cred.payloadData = new CredentialData(vcMap);
        cred.disclosures = disclosures;
        cred.verificationMethodKey = vmKey;
        return cred;
    }

    public static JOSECredential parse(String rawJWT, CredentialOptions opts) throws Exception {
        JOSECredential cred = parse(rawJWT);
        if (opts != null && (opts.isVerifyProof() || opts.isCheckExpiration() || opts.isValidateSchema()
                || opts.isCheckRevocation())) {
            cred.executeOptions(opts);
        }
        return cred;
    }

    public static JOSECredential parse(String rawJWT) throws Exception {
        String trimmed = rawJWT.trim();
        if (trimmed.startsWith("\"") && trimmed.endsWith("\"")) {
            trimmed = trimmed.substring(1, trimmed.length() - 1);
        }

        String issuerJWT;
        List<String> disclosures = new ArrayList<>();
        if (SDJWT.isSDJWT(trimmed)) {
            String[] segments = trimmed.split("~", -1);
            String tail = segments[segments.length - 1];
            if (!tail.isEmpty() && SDJWT.isJWT(tail)) {
                throw new Exception("key binding JWT is not supported");
            }
            ParsedSDJWT parsed = SDJWT.parse(trimmed);
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
            throw new Exception("invalid vc-jose typ: " + typ);
        }

        Map<String, Object> payloadMap = decodeJson(parts[1]);
        if (payloadMap.containsKey("vc") || payloadMap.containsKey("vp")) {
            throw new Exception("vc+jwt payload must not contain vc or vp claims");
        }
        requireJOSECredential(payloadMap);

        Map<String, Object> vcMap = payloadMap;
        if (vcMap.containsKey("_sd_alg") || !disclosures.isEmpty()) {
            vcMap = SDJWTReconstruct.reconstruct(vcMap, disclosures, true);
        }

        JOSECredential cred = new JOSECredential();
        cred.signingInput = parts[0] + "." + parts[1];
        cred.payloadData = new CredentialData(vcMap);
        cred.signature = parts.length == 3 ? parts[2] : "";
        cred.disclosures = disclosures;
        return cred;
    }

    @Override
    public void addProof(String privKeyHex) throws Exception {
        addProofByProvider(new DefaultSignerProvider(privKeyHex));
    }

    @Override
    public void addProofByProvider(SignerProvider signerProvider) throws Exception {
        addProofByProvider(signerProvider, null);
    }

    public void addProofByProvider(SignerProvider signerProvider, CredentialOptions opts) throws Exception {
        if (signerProvider == null) {
            throw new IllegalArgumentException("signer provider cannot be null");
        }
        if (signerProvider instanceof com.pila.credential.common.signer.P256SignerProvider) {
            String[] parts = signingInput.split("\\.");
            Map<String, Object> header = decodeJson(parts[0]);
            header.put("alg", "ES256");
            signingInput = encodeJson(header) + "." + parts[1];
        }
        JWTSigner signer = new JWTSigner(signerProvider);
        String newSignature = signer.signString(signingInput);

        JWTVerifier verifier = new JWTVerifier(CredentialConfig.getBaseURL());
        verifier.verifyJWT(signingInput + "." + newSignature);

        this.signature = newSignature;
        if (opts != null) {
            executeOptions(opts);
        }
    }

    @Override
    public byte[] getSigningInput() throws Exception {
        return signingInput.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public byte[] createProofSigning(byte[] docHash, Proof proof) throws Exception {
        throw new UnsupportedOperationException("createProofSigning applies to JSON-LD credentials only");
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
        JWTVerifier verifier = new JWTVerifier(CredentialConfig.getBaseURL());
        verifier.verifyJWT(signingInput + "." + signature);
    }

    @Override
    public Object serialize() throws Exception {
        String base = signingInput;
        if ((signature != null && !signature.isEmpty()) || !disclosures.isEmpty() || isDisclosable()) {
            base = base + "." + (signature != null ? signature : "");
        }
        if (!isDisclosable() && disclosures.isEmpty()) {
            return base;
        }
        StringBuilder out = new StringBuilder(base);
        for (String d : disclosures) {
            if (d == null || d.isEmpty()) {
                continue;
            }
            out.append('~').append(d);
        }
        return out + "~";
    }

    @Override
    public byte[] getContents() throws Exception {
        return MAPPER.writeValueAsBytes(payloadData);
    }

    @Override
    public String getType() {
        return "JOSE";
    }

    public CredentialData getPayloadData() {
        return payloadData;
    }

    public void setVerificationMethodKey(String verificationMethodKey) {
        if (verificationMethodKey != null && !verificationMethodKey.isEmpty()) {
            this.verificationMethodKey = verificationMethodKey;
        }
    }

    public boolean isDisclosable() {
        String typ = peekJwtTyp(signingInput);
        return TYPE_VC_SD_JWT.equals(typ) || ("application/" + TYPE_VC_SD_JWT).equals(typ);
    }

    public JOSECredential present(List<String> selectedDisclosures) throws Exception {
        if (signature == null || signature.isEmpty()) {
            throw new Exception("cannot present an unsigned credential");
        }
        if (!isDisclosable()) {
            throw new Exception("credential carries no disclosures; nothing to present selectively");
        }
        String issuerJWT = signingInput + "." + signature;
        return parse(SDJWT.buildSDJWTPresentation(issuerJWT, selectedDisclosures));
    }

    public String hash() throws Exception {
        if (signature == null || signature.isEmpty()) {
            throw new Exception("credential must be signed before hashing");
        }
        Object serialized = serialize();
        if (!(serialized instanceof String s)) {
            throw new Exception("unexpected serialized credential type");
        }
        byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                .digest(s.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(digest);
    }

    public void executeOptions(CredentialOptions opts) throws Exception {
        if (opts == null) {
            return;
        }
        if (opts.isValidateSchema()) {
            try {
                CredentialHelper.validateCredential(payloadData);
            } catch (UnsupportedOperationException ignored) {
                // Schema validation is not implemented in this SDK yet.
            }
        }
        if (opts.isVerifyProof()) {
            JWTVerifier verifier = new JWTVerifier(
                    opts.getDidBaseURL() != null && !opts.getDidBaseURL().isEmpty()
                            ? opts.getDidBaseURL()
                            : CredentialConfig.getBaseURL());
            verifier.verifyJWT(signingInput + "." + signature);
        }
        if (opts.isCheckExpiration()) {
            Object until = payloadData.get("validUntil");
            if (until instanceof String s) {
                java.time.Instant expiry = java.time.Instant.parse(s);
                if (!java.time.Instant.now().minusMillis(opts.getClockSkewLeewayMs()).isBefore(expiry)) {
                    throw new Exception("credential has expired");
                }
            }
        }
    }

    private static void requireJOSECredential(Map<String, Object> m) throws Exception {
        Object types = m.get("type");
        List<String> names = new ArrayList<>();
        if (types instanceof String s) {
            names.add(s);
        } else if (types instanceof List<?> list) {
            for (Object t : list) {
                if (t instanceof String ts) {
                    names.add(ts);
                }
            }
        }
        if (!names.contains("VerifiableCredential")) {
            throw new Exception("vc+jwt payload must include type VerifiableCredential");
        }
        if (!m.containsKey("issuer")) {
            throw new Exception("vc+jwt payload is missing issuer");
        }
        if (!m.containsKey("credentialSubject")) {
            throw new Exception("vc+jwt payload is missing credentialSubject");
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
