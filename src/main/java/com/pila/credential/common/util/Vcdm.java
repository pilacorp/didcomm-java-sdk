package com.pila.credential.common.util;

import com.pila.credential.common.error.CredentialException;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/** Small VC Data Model helpers shared by the vc and vp packages (Go {@code internal/vcdm} + {@code jwtutil}). */
public final class Vcdm {
    public static final String CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2";
    public static final String CONTEXT_V1 = "https://www.w3.org/2018/credentials/v1";

    private Vcdm() {
    }

    /** True when a {@code type} property (string or array) names {@code want}. */
    public static boolean hasType(Object v, String want) {
        if (v instanceof String s) {
            return s.equals(want);
        }
        if (v instanceof List<?> l) {
            for (Object e : l) {
                if (e instanceof String s && s.equals(want)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** First {@code @context} entry, or "" when it is not a string / array of strings. */
    public static String firstContext(Object v) {
        if (v instanceof String s) {
            return s;
        }
        if (v instanceof List<?> l && !l.isEmpty() && l.get(0) instanceof String s) {
            return s;
        }
        return "";
    }

    /** DID from a plain string or the {@code {"id": "did:..."}} object form; null when absent. */
    public static String didFromField(Object v) {
        if (v instanceof String s && !s.isEmpty()) {
            return s;
        }
        if (v instanceof Map<?, ?> m && m.get("id") instanceof String id && !id.isEmpty()) {
            return id;
        }
        return null;
    }

    /** Absent, null, "", and empty arrays/objects all count as empty. */
    public static boolean isEmptyValue(Object v) {
        if (v == null) {
            return true;
        }
        if (v instanceof String s) {
            return s.isEmpty();
        }
        if (v instanceof List<?> l) {
            return l.isEmpty();
        }
        if (v instanceof Map<?, ?> m) {
            return m.isEmpty();
        }
        return false;
    }

    /** Dot-path lookup through nested objects; null when any step is absent. */
    public static Object extractField(Map<String, Object> m, String path) {
        if (m == null) {
            return null;
        }
        Object current = m;
        for (String part : path.split("\\.", -1)) {
            if (!(current instanceof Map<?, ?> cur) || !cur.containsKey(part)) {
                return null;
            }
            current = cur.get(part);
        }
        return current;
    }

    /**
     * Enforces validFrom/validUntil (RFC 3339, strict) at the current time, widened by the leeway on both sides.
     */
    public static void checkValidityPeriod(String what, Object validFrom, Object validUntil, long leewayMs)
            throws Exception {
        Instant now = Instant.now();
        long leeway = Math.max(leewayMs, 0);
        if (validFrom != null && !(validFrom instanceof String f && f.isEmpty())) {
            Instant t = parseTime("validFrom", validFrom);
            if (now.plusMillis(leeway).isBefore(t)) {
                throw new CredentialException(CredentialException.Code.NOT_VALID_YET, what + " is not valid yet");
            }
        }
        if (validUntil != null && !(validUntil instanceof String u && u.isEmpty())) {
            Instant t = parseTime("validUntil", validUntil);
            if (now.minusMillis(leeway).isAfter(t)) {
                throw new CredentialException(CredentialException.Code.EXPIRED, what + " is expired");
            }
        }
    }

    private static Instant parseTime(String name, Object v) throws Exception {
        if (!(v instanceof String s)) {
            throw new Exception("failed to parse " + name + ": field \"" + name + "\" must be a string, got "
                    + v.getClass().getSimpleName());
        }
        try {
            return Rfc3339.parse(s);
        } catch (Exception e) {
            throw new Exception("failed to parse " + name + ": " + e.getMessage(), e);
        }
    }

    /** nbf/exp bound the signature, not the document (Go {@code jwtutil.CheckTimeClaims}). */
    public static void checkTimeClaims(Map<String, Object> claims, long leewayMs) throws Exception {
        Instant now = Instant.now();
        long leeway = Math.max(leewayMs, 0);
        Long nbf = numericClaim(claims, "nbf");
        if (nbf != null && now.plusMillis(leeway).isBefore(Instant.ofEpochSecond(nbf))) {
            throw new Exception("signature is not valid before " + Instant.ofEpochSecond(nbf) + " (nbf)");
        }
        Long exp = numericClaim(claims, "exp");
        if (exp != null && !now.minusMillis(leeway).isBefore(Instant.ofEpochSecond(exp))) {
            throw new Exception("signature expired at " + Instant.ofEpochSecond(exp) + " (exp)");
        }
    }

    private static Long numericClaim(Map<String, Object> claims, String name) throws Exception {
        Object raw = claims.get(name);
        if (raw == null) {
            return null;
        }
        if (!(raw instanceof Number n)) {
            throw new Exception("invalid " + name + " type: " + raw.getClass().getSimpleName());
        }
        long sec = n.longValue();
        if (sec <= 0) {
            throw new Exception("invalid " + name + " value: " + raw);
        }
        return sec;
    }
}
