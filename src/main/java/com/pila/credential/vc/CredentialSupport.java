package com.pila.credential.vc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.credentialstatus.CredentialStatus;
import com.pila.credential.common.error.CredentialException;
import com.pila.credential.common.error.CredentialException.Code;
import com.pila.credential.common.schema.JsonSchemaValidator;
import com.pila.credential.common.util.Vcdm;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Checks shared by every credential type (Go {@code credential_helper.go} / {@code json_credential.go}). */
final class CredentialSupport {
    static final String CREDENTIALS_V2_CONTEXT = Vcdm.CONTEXT_V2;
    static final String SUBJECT = "credentialSubject";
    /** Required on every credential by VCDM 2.0 sections 4.3, 4.5, 4.7, 4.8. */
    static final List<String> REQUIRED = List.of("@context", "type", "issuer", "credentialSubject");
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

    /** Properties a verifier decides on; they must never sit behind a disclosure. */
    private static final List<String> SECURED_CLAIMS = List.of(
            "@context", "type", "issuer", "validFrom", "validUntil", "issuanceDate", "expirationDate",
            "credentialStatus");

    private CredentialSupport() {
    }

    /** Presence only: value rules like the v2 context URL would reject the VC 1.1 documents we still sign. */
    static void requireCredentialProperties(Map<String, Object> m) throws Exception {
        for (String p : REQUIRED) {
            if (Vcdm.isEmptyValue(m.get(p))) {
                throw new Exception("credential is missing " + p);
            }
        }
    }

    static void requireV2Context(Object v) throws Exception {
        String first = Vcdm.firstContext(v);
        if (!CREDENTIALS_V2_CONTEXT.equals(first)) {
            throw new Exception("credential must name \"" + CREDENTIALS_V2_CONTEXT
                    + "\" first in @context, got \"" + first + "\"");
        }
    }

    /** The payload really is the VC 2.0 credential its vc+jwt media type claims. */
    static void requireJOSECredential(Map<String, Object> m) throws Exception {
        requireCredentialProperties(m);
        requireV2Context(m.get("@context"));
        if (!Vcdm.hasType(m.get("type"), "VerifiableCredential")) {
            throw new Exception("credential type must include VerifiableCredential, got " + m.get("type"));
        }
    }

    /** Refuses a token whose reconstruction introduced a secured claim, or whose signed payload hides some behind _sd. */
    static void requireSecuredClaimsSigned(Map<String, Object> signed, Map<String, Object> reconstructed)
            throws Exception {
        for (String claim : SECURED_CLAIMS) {
            if (!signed.containsKey(claim) && reconstructed.containsKey(claim)) {
                throw new Exception("\"" + claim + "\" was selectively disclosed; a verifier decides on it, "
                        + "so it must be part of the signed payload");
            }
        }
        if (signed.containsKey("_sd")) {
            throw new Exception("the signed payload hides top-level properties behind _sd; "
                    + "selective disclosure is for claims inside credentialSubject");
        }
    }

    /** Confines selective disclosure to the credentialSubject subtree. */
    static void requireDisclosableAtTopLevel(Map<String, Object> m, boolean subjectMayDisclose) throws Exception {
        if (m.containsKey("_sd")) {
            throw new Exception("the payload carries _sd at the root; selective disclosure belongs to claims inside "
                    + SUBJECT + ", because nothing at the top level may be withheld");
        }
        for (Map.Entry<String, Object> e : m.entrySet()) {
            if (SUBJECT.equals(e.getKey()) && subjectMayDisclose) {
                continue;
            }
            if (carriesSDMachinery(e.getValue())) {
                throw new Exception("selective disclosure is not permitted in \"" + e.getKey()
                        + "\"; only claims inside " + SUBJECT + " may be withheld");
            }
        }
    }

    /** True when the value holds an _sd digest array or an array-element {"...": digest} placeholder at any depth. */
    static boolean carriesSDMachinery(Object value) {
        if (value instanceof Map<?, ?> m) {
            if (m.containsKey("_sd")) {
                return true;
            }
            for (Object child : m.values()) {
                if (carriesSDMachinery(child)) {
                    return true;
                }
            }
        } else if (value instanceof List<?> l) {
            for (Object child : l) {
                if (child instanceof Map<?, ?> em && em.size() == 1 && em.containsKey("...")) {
                    return true;
                }
                if (carriesSDMachinery(child)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** SD-JWT machinery in a VC 1.1 document or JWT payload: _sd_alg (root or under vc), _sd, "..." placeholders. */
    static boolean carriesSDJWT(Map<String, Object> m) {
        if (m.containsKey("_sd_alg")) {
            return true;
        }
        if (m.get("vc") instanceof Map<?, ?> vc && vc.containsKey("_sd_alg")) {
            return true;
        }
        return carriesSDMachinery(m);
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> asMap(Object o) {
        return (Map<String, Object>) o;
    }

    static void checkExpiration(Map<String, Object> c, long leewayMs) throws Exception {
        Vcdm.checkValidityPeriod("credential", c.get("validFrom"), c.get("validUntil"), leewayMs);
    }

    /**
     * Validates the credential against every credentialSchema it names. credentialSchema is optional in VCDM 2.0
     * but this path exists to validate against it, so here it is required (Go {@code validateCredential}).
     */
    static void validateSchema(Map<String, Object> m, CredentialOptions opts) throws Exception {
        for (String key : prepend("credentialSchema", REQUIRED)) {
            if (Vcdm.isEmptyValue(m.get(key))) {
                throw new CredentialException(Code.SCHEMA_VALIDATION, key + " is required");
            }
        }
        Object schemas = m.get("credentialSchema");
        List<Object> list = schemas instanceof List<?> l ? new ArrayList<>(l) : List.of(schemas);
        Object instance = MAPPER.readValue(MAPPER.writeValueAsBytes(m), Object.class);
        for (Object schema : list) {
            if (!(schema instanceof Map<?, ?> sm) || sm.get("id") == null) {
                throw new CredentialException(Code.SCHEMA_VALIDATION, "credentialSchema.id is required");
            }
            if (!(sm.get("id") instanceof String id) || id.isEmpty()) {
                throw new CredentialException(Code.SCHEMA_VALIDATION,
                        "credentialSchema.id must be a non-empty string");
            }
            byte[] schemaBytes;
            if (opts != null && opts.getSchemaLoader() != null) {
                try {
                    schemaBytes = opts.getSchemaLoader().load(id);
                } catch (Exception e) {
                    throw new CredentialException(Code.SCHEMA_VALIDATION,
                            "failed to load schema via custom loader: " + e.getMessage(), e);
                }
                if (schemaBytes == null || schemaBytes.length == 0) {
                    throw new CredentialException(Code.SCHEMA_VALIDATION,
                            "failed to load schema via custom loader: schema is empty");
                }
            } else {
                schemaBytes = loadSchemaByReference(id);
            }
            List<String> errors;
            try {
                errors = JsonSchemaValidator.validate(schemaBytes, instance);
            } catch (Exception e) {
                throw new CredentialException(Code.SCHEMA_VALIDATION, "failed to validate schema: " + e.getMessage(), e);
            }
            if (!errors.isEmpty()) {
                throw new CredentialException(Code.SCHEMA_VALIDATION, "credential validation failed: " + errors);
            }
        }
    }

    private static List<String> prepend(String first, List<String> rest) {
        List<String> out = new ArrayList<>();
        out.add(first);
        out.addAll(rest);
        return out;
    }

    /** Default loader: http(s) GET or file: URI. */
    private static byte[] loadSchemaByReference(String id) throws Exception {
        try {
            URI uri = URI.create(id);
            if ("file".equals(uri.getScheme())) {
                return Files.readAllBytes(Path.of(uri));
            }
            if ("http".equals(uri.getScheme()) || "https".equals(uri.getScheme())) {
                HttpResponse<byte[]> resp = HTTP.send(
                        HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(10)).GET().build(),
                        HttpResponse.BodyHandlers.ofByteArray());
                if (resp.statusCode() != 200) {
                    throw new Exception("schema endpoint returned " + resp.statusCode());
                }
                return resp.body();
            }
        } catch (Exception e) {
            throw new CredentialException(Code.SCHEMA_VALIDATION,
                    "failed to validate schema: cannot load " + id + ": " + e.getMessage(), e);
        }
        throw new CredentialException(Code.SCHEMA_VALIDATION,
                "failed to validate schema: cannot load " + id + ": unsupported scheme");
    }

    /**
     * credentialStatus absent or empty means the credential does not use revocation; otherwise it must be a
     * single object naming a W3C bitstring status list and an index, and the bit at that index must be clear.
     */
    static void checkRevocation(Map<String, Object> c, CredentialOptions opts) throws Exception {
        Object raw = c.get("credentialStatus");
        if (raw == null) {
            return;
        }
        if (!(raw instanceof Map<?, ?> status)) {
            throw new Exception("credentialStatus must be an object");
        }
        if (status.isEmpty()) {
            return;
        }
        if (!(status.get("statusListCredential") instanceof String listUrl) || listUrl.isEmpty()) {
            throw new Exception(status.get("statusListCredential") == null
                    ? "credentialStatus.statusListCredential is required"
                    : "credentialStatus.statusListCredential must be a non-empty string");
        }
        if (!(status.get("statusListIndex") instanceof String idx) || idx.isEmpty()) {
            throw new Exception(status.get("statusListIndex") == null
                    ? "credentialStatus.statusListIndex is required"
                    : "credentialStatus.statusListIndex must be a non-empty string");
        }
        int position;
        try {
            position = Integer.parseInt(idx);
        } catch (NumberFormatException e) {
            throw new Exception("invalid credentialStatus.statusListIndex: " + e.getMessage(), e);
        }
        boolean revoked;
        try {
            revoked = CredentialStatus.fetchAndCheckRevocation(listUrl, position,
                    opts != null ? opts.getStatusFetcher() : null);
        } catch (Exception e) {
            throw new Exception("failed to check revocation: " + e.getMessage(), e);
        }
        if (revoked) {
            throw new CredentialException(Code.REVOKED, "credential is revoked");
        }
    }

    /** Checks run on the content before any signature is made or verified (Go {@code executeOptions} prefix). */
    static void runContentChecks(Map<String, Object> data, CredentialOptions o) throws Exception {
        try {
            if (o.isValidateSchema()) {
                validateSchema(data, o);
            }
            if (o.isCheckRevocation()) {
                checkRevocation(data, o);
            }
        } catch (CredentialException e) {
            throw e;
        } catch (Exception e) {
            throw new Exception("credential verification failed: " + e.getMessage(), e);
        }
    }

    /** JWT/JOSE: a second signature would replace the first; refused unless withReplaceProof. */
    static void refuseOverwrite(String current, CredentialOptions o) throws CredentialException {
        if (current == null || current.isEmpty() || o.isReplaceProof()) {
            return;
        }
        throw new CredentialException(Code.ALREADY_SIGNED,
                "credential is already signed; signing again would replace that signature — "
                        + "pass withReplaceProof to do so deliberately");
    }

    /** JSON-LD appends proofs; honouring replace would silently append, so it is refused. */
    static void refuseReplaceOnJSONLD(CredentialOptions o) throws CredentialException {
        if (o.isReplaceProof()) {
            throw new CredentialException(Code.UNSUPPORTED_OPTION,
                    "withReplaceProof does not apply to JSON-LD: proofs are appended to the proof set, not replaced; "
                            + "build a new credential without the proof to re-sign");
        }
    }

    /** Options only the constructors apply: the header kid and SD options. Refused at signing, not ignored. */
    static void rejectBuildTimeOptions(CredentialOptions o) throws CredentialException {
        if (o.getVerificationMethodKey() != null && !o.getVerificationMethodKey().isEmpty()) {
            throw new CredentialException(Code.UNSUPPORTED_OPTION,
                    "withVerificationMethodKey cannot be applied when signing a JWT: the header's kid was fixed when "
                            + "the token was built — pass the option to newJWTCredential or JOSECredential.create");
        }
        if (o.hasSDOptions()) {
            throw new CredentialException(Code.UNSUPPORTED_OPTION,
                    "SD-JWT options cannot be applied when signing: the disclosures were fixed when the token was "
                            + "built — pass them to JOSECredential.create");
        }
    }
}
