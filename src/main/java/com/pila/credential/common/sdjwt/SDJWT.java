package com.pila.credential.common.sdjwt;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * SD-JWT string helpers, disclosure hashing, and presentation envelope.
 */
public final class SDJWT {
    public static final String ALG_SHA256 = "sha-256";
    public static final String ALG_SHA384 = "sha-384";
    public static final String ALG_SHA512 = "sha-512";
    public static final String DEFAULT_HASH_ALGORITHM = ALG_SHA256;

    private static final Pattern JWT_PATTERN =
            Pattern.compile("^[A-Za-z0-9\\-_]+\\.[A-Za-z0-9\\-_]+(\\.[A-Za-z0-9\\-_]+)?$");
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final Map<String, Boolean> SUPPORTED = Map.of(
            ALG_SHA256, true,
            ALG_SHA384, true,
            ALG_SHA512, true);

    private SDJWT() {
    }

    public static boolean isSupportedHashAlgorithm(String alg) {
        return alg != null && Boolean.TRUE.equals(SUPPORTED.get(alg));
    }

    public static boolean isJWT(String s) {
        if (s == null) {
            return false;
        }
        String trimmed = s.trim();
        if (trimmed.endsWith(".")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return JWT_PATTERN.matcher(trimmed).matches();
    }

    public static boolean isSDJWT(String raw) {
        if (raw == null || raw.isEmpty()) {
            return false;
        }
        String s = raw.trim();
        if (s.startsWith("\"") && s.endsWith("\"")) {
            s = s.substring(1, s.length() - 1);
        }
        int idx = s.indexOf('~');
        if (idx < 0) {
            return false;
        }
        return isJWT(s.substring(0, idx));
    }

    public static ParsedSDJWT parse(String raw) throws Exception {
        if (!isSDJWT(raw)) {
            throw new Exception("invalid SD-JWT format");
        }
        String s = raw.trim();
        if (s.startsWith("\"") && s.endsWith("\"")) {
            s = s.substring(1, s.length() - 1);
        }
        String[] parts = s.split("~", -1);
        if (parts.length < 2) {
            throw new Exception("invalid SD-JWT: missing disclosures or terminator");
        }
        String issuer = parts[0];
        List<String> disclosures = new ArrayList<>();
        for (int i = 1; i < parts.length; i++) {
            String seg = parts[i].trim();
            if (seg.isEmpty()) {
                continue;
            }
            if (i == parts.length - 1 && isJWT(seg) && i > 1) {
                break;
            }
            disclosures.add(seg);
        }
        return new ParsedSDJWT(issuer, disclosures);
    }

    public static String buildSDJWTPresentation(String issuerSignedJWT, List<String> selectedDisclosures) {
        StringBuilder out = new StringBuilder(issuerSignedJWT);
        if (selectedDisclosures != null) {
            for (String sel : selectedDisclosures) {
                if (sel == null || sel.isEmpty()) {
                    continue;
                }
                out.append('~').append(sel);
            }
        }
        return out + "~";
    }

    public static String hashDisclosure(String sdAlg, String disclosure) throws Exception {
        byte[] bytes = disclosure.getBytes(StandardCharsets.UTF_8);
        MessageDigest digest;
        switch (sdAlg) {
            case ALG_SHA256 -> digest = MessageDigest.getInstance("SHA-256");
            case ALG_SHA384 -> digest = MessageDigest.getInstance("SHA-384");
            case ALG_SHA512 -> digest = MessageDigest.getInstance("SHA-512");
            default -> throw new Exception("unsupported sd_alg \"" + sdAlg + "\"");
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest.digest(bytes));
    }

    public static String randomSalt() {
        byte[] buf = new byte[16];
        RANDOM.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    static DisclosureInfo parseDisclosure(String disc) throws Exception {
        byte[] decoded;
        try {
            decoded = Base64.getUrlDecoder().decode(disc);
        } catch (IllegalArgumentException e) {
            throw new Exception("failed to decode disclosure \"" + disc + "\"");
        }
        List<?> arr;
        try {
            arr = MAPPER.readValue(decoded, new TypeReference<List<?>>() {
            });
        } catch (Exception e) {
            throw new Exception("failed to unmarshal disclosure: " + e.getMessage());
        }
        if (arr == null) {
            throw new Exception("failed to unmarshal disclosure: not an array");
        }
        if (arr.size() != 2 && arr.size() != 3) {
            throw new Exception(
                    "invalid disclosure structure: expected 2 or 3 elements, got " + arr.size());
        }
        if (!(arr.get(0) instanceof String salt)) {
            throw new Exception("disclosure salt must be a string");
        }
        if (arr.size() == 3) {
            if (!(arr.get(1) instanceof String fieldName)) {
                throw new Exception("disclosure field name must be a string");
            }
            return new DisclosureInfo(disc, salt, fieldName, arr.get(2), false);
        }
        return new DisclosureInfo(disc, salt, "", arr.get(1), true);
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> deepCopyMap(Map<String, Object> source) throws Exception {
        byte[] bytes = MAPPER.writeValueAsBytes(source);
        return MAPPER.readValue(bytes, new TypeReference<Map<String, Object>>() {
        });
    }

    static Map<String, Object> newDisclosurePlaceholder(String digest) {
        Map<String, Object> placeholder = new HashMap<>();
        placeholder.put("...", digest);
        return placeholder;
    }
}
