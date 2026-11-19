package com.pila.credential.vp;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Pattern;

/** Auto-detecting presentation parser (Go {@code ParsePresentation}). */
public final class PresentationParser {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Pattern JWT_PATTERN = Pattern.compile("^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+$");

    private PresentationParser() {
    }

    static boolean isJWTShaped(String s) {
        return JWT_PATTERN.matcher(s).matches();
    }

    public static Presentation parsePresentation(byte[] raw) throws Exception {
        return parsePresentation(raw, null);
    }

    /** JSON-LD, vp+jwt (JOSE) or VC 1.1 JWT; an SD-JWT shaped token is refused. */
    public static Presentation parsePresentation(byte[] raw, PresentationOptions opts) throws Exception {
        if (raw == null || raw.length == 0) {
            throw new Exception("presentation is empty");
        }
        try {
            if (MAPPER.readValue(raw, new TypeReference<Map<String, Object>>() {
            }) != null) {
                return JSONPresentation.parse(raw, opts);
            }
        } catch (com.fasterxml.jackson.core.JsonProcessingException notJson) {
            // not a JSON object: try the token forms below
        }
        String val = new String(raw, StandardCharsets.UTF_8).trim();
        if (val.length() >= 2 && val.startsWith("\"") && val.endsWith("\"")) {
            val = val.substring(1, val.length() - 1).trim();
        }
        if (isJWTShaped(val)) {
            try {
                Map<String, Object> header = MAPPER.readValue(Base64.getUrlDecoder().decode(val.split("\\.")[0]),
                        new TypeReference<Map<String, Object>>() {
                        });
                if (header.get("typ") instanceof String typ && JOSEPresentation.isJOSEPresentationTyp(typ)) {
                    return JOSEPresentation.parse(val, opts);
                }
            } catch (IllegalArgumentException | com.fasterxml.jackson.core.JsonProcessingException ignored) {
                // an undecodable header falls through to the VC 1.1 JWT path, which reports it
            }
            return JWTPresentation.parse(val, opts);
        }
        int tilde = val.indexOf('~');
        if (tilde > 0 && isJWTShaped(val.substring(0, tilde))) {
            throw new Exception("presentation carries SD-JWT disclosures, which are not supported for presentations");
        }
        throw new Exception("failed to parse presentation");
    }

    /** Parse + embedded credential validation + proof verification. */
    public static Presentation parsePresentationWithValidation(byte[] raw) throws Exception {
        return parsePresentation(raw, new PresentationOptions().withVCValidation().withVerifyProof());
    }
}
