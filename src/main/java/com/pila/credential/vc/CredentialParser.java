package com.pila.credential.vc;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Map;
import java.util.regex.Pattern;

/**
 * Parser for credentials in various formats.
 */
public class CredentialParser {
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
            Map<String, Object> jsonMap = objectMapper.readValue(rawCredential, Map.class);
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

    /**
     * Parses a credential from various formats into a Credential.
     * Currently only supports JSON credentials.
     */
    public static Credential parseCredential(byte[] rawCredential) throws Exception {
        if (rawCredential == null || rawCredential.length == 0) {
            throw new Exception("JSON string is empty");
        }

        if (isJSONCredential(rawCredential)) {
            return JSONCredential.parseJSONCredential(rawCredential);
        }

        // Try as JWT string
        String valStr = new String(rawCredential);
        if (isJWTCredential(valStr)) {
            return JWTCredential.parseJWTCredential(valStr);
        }

        throw new Exception("failed to parse credential: not a valid JWT or embedded credential");
    }

    /**
     * Parses a credential with validation (schema validation is bypassed).
     */
    public static Credential parseCredentialWithValidation(byte[] rawCredential) throws Exception {
        // TODO: Implement JSON schema validation for Verifiable Credentials
        // - Load JSON schema from credentialSchema field or external URL
        // - Validate credential structure against JSON schema
        // - Validate required fields (@context, type, issuer, credentialSubject, etc.)
        // - Validate field types and formats according to schema
        // - Throw validation errors if schema validation fails
        // Schema validation is bypassed, just parse normally
        return parseCredential(rawCredential);
    }
}
