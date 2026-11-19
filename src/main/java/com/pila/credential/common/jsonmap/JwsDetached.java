package com.pila.credential.common.jsonmap;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** RFC 7797 detached JWS helpers (b64:false, crit:[b64]). */
public final class JwsDetached {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();

    private JwsDetached() {
    }

    public static String encodeHeader(String alg) throws Exception {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", alg);
        header.put("b64", false);
        header.put("crit", List.of("b64"));
        return URL_ENCODER.encodeToString(MAPPER.writeValueAsBytes(header));
    }

    public static String algFromEncodedHeader(String encHeader) throws Exception {
        byte[] headerBytes = URL_DECODER.decode(encHeader);
        Map<String, Object> hdr = MAPPER.readValue(headerBytes, new TypeReference<Map<String, Object>>() {
        });
        Object alg = hdr.get("alg");
        if (!(alg instanceof String)) {
            throw new Exception("jws header missing alg");
        }
        Object b64 = hdr.get("b64");
        if (!(b64 instanceof Boolean) || (Boolean) b64) {
            throw new Exception("jws header b64 must be false");
        }
        Object crit = hdr.get("crit");
        if (!(crit instanceof List) || !((List<?>) crit).contains("b64")) {
            throw new Exception("jws header crit must include b64");
        }
        return (String) alg;
    }

    public static byte[] signingInput(String encHeader, byte[] payload) {
        byte[] headerBytes = encHeader.getBytes(StandardCharsets.US_ASCII);
        byte[] out = new byte[headerBytes.length + 1 + payload.length];
        System.arraycopy(headerBytes, 0, out, 0, headerBytes.length);
        out[headerBytes.length] = '.';
        System.arraycopy(payload, 0, out, headerBytes.length + 1, payload.length);
        return out;
    }

    public static String[] splitDetachedJws(String jws) {
        int idx = -1;
        for (int i = 0; i + 1 < jws.length(); i++) {
            if (jws.charAt(i) == '.' && jws.charAt(i + 1) == '.') {
                idx = i;
                break;
            }
        }
        if (idx <= 0) {
            return null;
        }
        String header = jws.substring(0, idx);
        String sig = jws.substring(idx + 2);
        if (header.isEmpty() || sig.isEmpty()) {
            return null;
        }
        return new String[] { header, sig };
    }

    /**
     * Decodes a base64url JWS signature with a single canonical spelling (Go Strict() parity).
     */
    public static byte[] decodeCanonicalSignature(String encSig) throws Exception {
        byte[] decoded = URL_DECODER.decode(encSig);
        String reencoded = URL_ENCODER.encodeToString(decoded);
        if (!reencoded.equals(encSig)) {
            throw new Exception("non-canonical base64url jws signature");
        }
        return decoded;
    }
}
