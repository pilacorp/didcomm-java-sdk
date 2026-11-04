package com.pila.credential.common.jwt;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.crypto.Crypto;
import com.pila.credential.common.verificationmethod.CredentialResolver;
import com.pila.credential.common.verificationmethod.DIDDocument;
import com.pila.credential.common.verificationmethod.RevocationReasons;
import com.pila.credential.common.verificationmethod.StrictPurposeCheck;
import com.pila.credential.common.verificationmethod.VerificationMethodEntry;
import com.pila.credential.common.verificationmethod.VerificationMethodKeyKind;
import com.pila.credential.common.verificationmethod.VerificationMethodMaterial;
import com.pila.credential.common.verificationmethod.VerificationMethodResolver;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Verifies ES256K / ES256 JWTs (vc+jwt / vp+jwt) with go-credential-sdk parity.
 *
 * <p>The verifier binds the header {@code kid} to the signer the payload names
 * (issuer for a credential, holder for a presentation): the document is
 * resolved by that signer DID, and the {@code kid} must name a verification
 * method inside <em>that</em> document. The header algorithm must match the
 * key the method holds, and the proof-purpose / revocation checks run after the
 * cryptographic check.
 */
public class JWTVerifier {

    private static final String ALG_ES256K = "ES256K";
    private static final String ALG_ES256 = "ES256";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final CredentialResolver resolver;

    /**
     * Creates a verifier backed by the HTTP DID resolver at {@code didBaseURL}.
     */
    public JWTVerifier(String didBaseURL) {
        this.resolver = new VerificationMethodResolver(didBaseURL);
    }

    /**
     * Creates a verifier backed by an injected resolver (offline / tests).
     */
    public JWTVerifier(CredentialResolver resolver) {
        this.resolver = resolver;
    }

    /**
     * Verifies a JWT token, binding the signing key to the payload's signer.
     *
     * @param tokenString the {@code header.payload.signature} JWT
     * @throws Exception if verification fails
     */
    public void verifyJWT(String tokenString) throws Exception {
        String[] parts = tokenString.split("\\.");
        if (parts.length != 3) {
            throw new Exception("invalid JWT format");
        }

        Map<String, Object> header = decode(parts[0]);
        Object algObj = header.get("alg");
        String alg = algObj instanceof String s ? s : null;
        if (alg == null || (!ALG_ES256K.equals(alg) && !ALG_ES256.equals(alg))) {
            throw new Exception("unsupported algorithm: " + algObj);
        }

        Object kidObj = header.get("kid");
        if (!(kidObj instanceof String)) {
            throw new Exception("kid not found in header");
        }
        String kid = (String) kidObj;

        if (resolver == null) {
            throw new Exception("document resolver is not configured");
        }

        // Which property names the signer depends on the kind: a credential is
        // signed by its issuer, a presentation by its holder. The purpose is
        // resolved before the signer, and both come from the payload — not from
        // the attacker-chosen kid.
        Map<String, Object> body = decode(parts[1]);
        String purpose = jwtProofPurpose(header, body);
        String signer = jwtSigner(body, purpose);

        // Resolve the document for the signer the body names; FindVerificationMethod
        // then rejects a kid that does not belong to that signer's document.
        DIDDocument doc = resolver.resolveDocument(signer);
        VerificationMethodEntry vm = findVerificationMethod(doc, kid);

        // The header must not claim an algorithm the method's key cannot produce.
        VerificationMethodKeyKind kind = VerificationMethodKeyKind.fromEntry(vm);
        String wantAlg = algForKeyKind(kind);
        if (wantAlg == null) {
            throw new Exception("verification method '" + vm.getId() + "' has an unsupported key type for JWT");
        }
        if (!alg.equals(wantAlg)) {
            throw new Exception("JWT alg \"" + alg + "\" does not match verification method '" + vm.getId()
                    + "', which holds a " + kind + " key");
        }

        PublicKey publicKey = VerificationMethodMaterial.ecPublicKeyFromEntry(vm);

        String signingString = parts[0] + "." + parts[1];
        byte[] signature = Base64.getUrlDecoder().decode(parts[2]);
        if (signature.length == 65) {
            signature = Arrays.copyOf(signature, 64);
        } else if (signature.length != 64) {
            throw new Exception("invalid signature length: got " + signature.length + ", want 64 or 65");
        }

        // alg was matched to the key kind above, so publicKey is on the curve alg
        // names; ES256K (secp256k1) and ES256 (P-256) share the same ECDSA check.
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(signingString.getBytes(StandardCharsets.UTF_8));
        if (!Crypto.verifyEcdsaRaw(publicKey, digest, signature)) {
            throw new Exception("signature verification failed");
        }

        enforceStrictPurpose(doc, vm, purpose, jwtIssuedAt(body));
    }

    private static String algForKeyKind(VerificationMethodKeyKind kind) {
        return switch (kind) {
            case P256 -> ALG_ES256;
            case SECP256K1 -> ALG_ES256K;
            default -> null;
        };
    }

    private static VerificationMethodEntry findVerificationMethod(DIDDocument doc, String kid) throws Exception {
        if (doc == null) {
            throw new Exception("did document is nil");
        }
        String want = normalizeVmUrl(doc.getId(), kid);
        if (doc.getVerificationMethod() != null) {
            for (VerificationMethodEntry vm : doc.getVerificationMethod()) {
                if (want.equals(vm.getId())) {
                    return vm;
                }
            }
        }
        throw new Exception("verification method '" + kid + "' not found in DID '" + doc.getId() + "' document");
    }

    private static String normalizeVmUrl(String did, String kid) {
        if (kid == null || kid.isEmpty()) {
            return "";
        }
        if (kid.startsWith("did:")) {
            return kid;
        }
        if (kid.startsWith("#")) {
            return did + kid;
        }
        return did + "#" + kid;
    }

    // --- proof purpose -------------------------------------------------------

    private static String jwtProofPurpose(Map<String, Object> header, Map<String, Object> body) throws Exception {
        String carried = purposeFromBody(body);
        String declared = purposeFromTyp(header);
        if (!carried.isEmpty() && !declared.isEmpty() && !carried.equals(declared)) {
            throw new Exception("JWT typ " + header.get("typ") + " implies proofPurpose " + declared
                    + " but its payload is a " + documentKind(carried));
        }
        if (!carried.isEmpty()) {
            return carried;
        }
        if (!declared.isEmpty()) {
            return declared;
        }
        throw new Exception("JWT has neither vc/vp claims nor vc+jwt/vp+jwt typ; cannot determine proofPurpose");
    }

    private static String purposeFromTyp(Map<String, Object> header) {
        String typ = header.get("typ") instanceof String s ? s : "";
        return switch (typ) {
            case "vc+jwt", "application/vc+jwt", "vc+sd-jwt", "application/vc+sd-jwt" -> "assertionMethod";
            case "vp+jwt", "application/vp+jwt" -> "authentication";
            default -> "";
        };
    }

    private static String purposeFromBody(Map<String, Object> body) throws Exception {
        boolean hasVC = body.containsKey("vc");
        boolean hasVP = body.containsKey("vp");
        if (hasVC && hasVP) {
            throw new Exception("JWT carries both vc and vp claims; its kind is ambiguous");
        }
        if (hasVC) {
            return "assertionMethod";
        }
        if (hasVP) {
            return "authentication";
        }
        Object type = body.get("type");
        if (type instanceof List<?> list) {
            String found = "";
            for (Object v : list) {
                String p = purposeFromType(v instanceof String s ? s : "");
                if (p.isEmpty()) {
                    continue;
                }
                if (!found.isEmpty() && !found.equals(p)) {
                    throw new Exception("JWT type names both a credential and a presentation; its kind is ambiguous");
                }
                found = p;
            }
            return found;
        }
        if (type instanceof String s) {
            return purposeFromType(s);
        }
        return "";
    }

    private static String purposeFromType(String t) {
        if ("VerifiableCredential".equals(t)) {
            return "assertionMethod";
        }
        if ("VerifiablePresentation".equals(t)) {
            return "authentication";
        }
        return "";
    }

    private static String documentKind(String purpose) {
        return "assertionMethod".equals(purpose) ? "credential" : "presentation";
    }

    // --- signer --------------------------------------------------------------

    private static String jwtSigner(Map<String, Object> body, String purpose) throws Exception {
        String field = "assertionMethod".equals(purpose) ? "issuer" : "holder";

        // VC 1.1 nests the document under a vc/vp claim; read the property there
        // when present so a nested issuer cannot disagree with iss unnoticed.
        Map<String, Object> doc = body;
        if (body.get("vc") instanceof Map<?, ?> m) {
            doc = castMap(m);
        } else if (body.get("vp") instanceof Map<?, ?> m) {
            doc = castMap(m);
        }

        // Guard against a case-variant duplicate key: a downstream consumer that
        // matches the field case-insensitively would read a value this lookup
        // never sees, letting a signer name the victim under an unchecked key.
        for (String k : doc.keySet()) {
            if (!k.equals(field) && k.equalsIgnoreCase(field)) {
                throw new Exception("JWT carries \"" + k + "\", which differs from " + field + " only by case");
            }
        }

        boolean present = doc.containsKey(field);
        String claimed = didFromClaim(doc.get(field));
        if (present && claimed.isEmpty()) {
            throw new Exception("JWT " + field + " must be a string or an object with a string id");
        }

        String iss = body.get("iss") instanceof String s ? s : "";
        if (!iss.isEmpty() && !claimed.isEmpty() && !iss.equals(claimed)) {
            throw new Exception("JWT iss \"" + iss + "\" does not match " + field + " \"" + claimed + "\"");
        }
        if (!iss.isEmpty()) {
            return iss;
        }
        if (!claimed.isEmpty()) {
            return claimed;
        }
        throw new Exception("JWT names no signer: both iss and " + field + " are absent");
    }

    private static String didFromClaim(Object v) {
        if (v instanceof String s) {
            return s;
        }
        if (v instanceof Map<?, ?> m && m.get("id") instanceof String s) {
            return s;
        }
        return "";
    }

    // --- revocation / purpose check -----------------------------------------

    private static Instant jwtIssuedAt(Map<String, Object> body) {
        Object iat = body.get("iat");
        if (iat instanceof Number n) {
            return Instant.ofEpochSecond(n.longValue());
        }
        if (iat instanceof String s && !s.isBlank()) {
            try {
                return Instant.ofEpochSecond(Long.parseLong(s.trim()));
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private static void enforceStrictPurpose(DIDDocument doc, VerificationMethodEntry vm, String purpose,
            Instant issuedAt) throws Exception {
        boolean softRevoked = vm.getRevoked() != null && !vm.getRevoked().isEmpty();
        if (softRevoked && issuedAt == null
                && !RevocationReasons.isHardRevocationReason(vm.getRevocationReason())) {
            throw new Exception("verification method '" + vm.getId() + "' was revoked at " + vm.getRevoked()
                    + " (missing iat for time-based revocation check)");
        }
        // JWTs carry no proof.created; the soft-revocation comparison uses iat.
        StrictPurposeCheck.enforce(doc, vm, purpose, issuedAt != null ? issuedAt.toString() : "");
    }

    private static Map<String, Object> decode(String b64) throws Exception {
        byte[] bytes = Base64.getUrlDecoder().decode(b64);
        return MAPPER.readValue(bytes, new TypeReference<Map<String, Object>>() {
        });
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> castMap(Map<?, ?> m) {
        return (Map<String, Object>) m;
    }
}
