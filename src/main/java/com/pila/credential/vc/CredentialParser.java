package com.pila.credential.vc;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.sdjwt.SDJWT;

import com.pila.credential.common.util.Vcdm;

import java.util.Map;
import java.util.regex.Pattern;

/**
 * Parser for credentials in various formats.
 */
public class CredentialParser {
    public static final String TYPE_ENVELOPED_VC = "EnvelopedVerifiableCredential";
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final Pattern JWT_PATTERN = Pattern.compile("^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+$");

    /**
     * Checks if the raw bytes represent a valid JSON credential.
     */
    public static boolean isJSONCredential(byte[] rawCredential) {
        if (rawCredential == null || rawCredential.length == 0) {
            return false;
        }

        try {
            // Check if it's valid JSON
            objectMapper.readTree(rawCredential);

            // Try to parse as a map
            Map<String, Object> jsonMap = objectMapper.readValue(rawCredential,
                    new TypeReference<Map<String, Object>>() {
                    });

            return jsonMap != null;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Checks if the string represents a JWT credential.
     */
    public static boolean isJWTCredential(String valStr) {
        if (valStr == null || valStr.isEmpty()) {
            return false;
        }

        valStr = valStr.trim();
        // Remove surrounding quotes if present
        if (valStr.startsWith("\"") && valStr.endsWith("\"")) {
            valStr = valStr.substring(1, valStr.length() - 1);
        }

        return JWT_PATTERN.matcher(valStr).matches();
    }

    public static Credential parseCredential(byte[] rawCredential) throws Exception {
        return parseCredential(rawCredential, null);
    }

    /**
     * Parses a credential from JSON-LD, an EnvelopedVerifiableCredential, a vc+jwt / vc+sd-jwt (JOSE) token or a
     * VC 1.1 JWT, applying {@code opts} (proof, schema, revocation, expiration, resolver, ...).
     */
    public static Credential parseCredential(byte[] rawCredential, CredentialOptions opts) throws Exception {
        if (rawCredential == null || rawCredential.length == 0) {
            throw new Exception("JSON string is empty");
        }

        if (isJSONCredential(rawCredential)) {
            // EnvelopedVerifiableCredential per VCDM 2.0 4.13: both halves are load-bearing. Unwrapping on the id
            // alone would let any JSON borrow an id and be read as whatever that id points at.
            Map<String, Object> peek = objectMapper.readValue(rawCredential,
                    new TypeReference<Map<String, Object>>() {
                    });
            if (peek.get("id") instanceof String id) {
                for (String prefix : new String[] {
                        "data:application/" + JOSECredential.TYPE_VC_JWT + ",",
                        "data:application/" + JOSECredential.TYPE_VC_SD_JWT + "," }) {
                    if (!id.startsWith(prefix)) {
                        continue;
                    }
                    if (!Vcdm.hasType(peek.get("type"), TYPE_ENVELOPED_VC)) {
                        throw new Exception("credential carries a " + prefix + " id but its type is not "
                                + TYPE_ENVELOPED_VC);
                    }
                    // Parsed as vc-jose-cose rather than recursing, so a VC 1.1 JWT hidden in a v2 envelope is
                    // refused and the nesting stays one level.
                    return JOSECredential.parse(id.substring(prefix.length()), opts);
                }
            }
            return JSONCredential.parseJSONCredential(rawCredential, opts);
        }

        String valStr = new String(rawCredential, java.nio.charset.StandardCharsets.UTF_8).trim();
        if (valStr.length() >= 2 && valStr.startsWith("\"") && valStr.endsWith("\"")) {
            valStr = valStr.substring(1, valStr.length() - 1).trim();
        }
        if (SDJWT.isSDJWT(valStr) || isJWTCredential(valStr)) {
            String typ = JOSECredential.peekJwtTyp(valStr);
            // vc+jwt and vc+sd-jwt are both vc-jose-cose. A tilde alone does not decide it: a VC 1.1 SD-JWT has the
            // same shape with typ "JWT"; it goes to the 1.1 path below, which refuses it (SDJWTRequiresJOSE).
            if (typ != null && typ.endsWith("+sd-jwt") && !JOSECredential.isJOSECredentialTyp(typ)) {
                throw new Exception("failed to parse credential: unsupported SD-JWT typ \"" + typ
                        + "\": only vc+sd-jwt is read");
            }
            if (JOSECredential.isJOSECredentialTyp(typ)) {
                return JOSECredential.parse(valStr, opts);
            }
            return JWTCredential.parseJWTCredential(valStr, opts);
        }

        throw new Exception("failed to parse credential: not a valid JSON, SD-JWT, or JWT credential");
    }

    public static Credential parseCredentialWithValidation(byte[] rawCredential) throws Exception {
        return parseCredentialWithValidation(rawCredential, null);
    }

    /** Parse + schema validation + proof verification (Go {@code ParseCredentialWithValidation}). */
    public static Credential parseCredentialWithValidation(byte[] rawCredential, CredentialOptions opts)
            throws Exception {
        CredentialOptions o = CredentialOptions.orEmpty(opts).copy();
        o.setValidateSchema(true);
        o.setVerifyProof(true);
        return parseCredential(rawCredential, o);
    }
}
