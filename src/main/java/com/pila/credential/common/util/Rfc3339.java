package com.pila.credential.common.util;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;

/** RFC 3339 helpers matching Go {@code time.RFC3339} (whole seconds on write, strict on read). */
public final class Rfc3339 {
    private Rfc3339() {
    }

    /** Whole-second UTC, e.g. {@code 2024-01-02T03:04:05Z}. */
    public static String format(Instant t) {
        return t.truncatedTo(ChronoUnit.SECONDS).toString();
    }

    public static String now() {
        return format(Instant.now());
    }

    private static final java.util.regex.Pattern STRICT = java.util.regex.Pattern.compile(
            "(\\d{4})-(\\d{2})-(\\d{2})T(\\d{2}):(\\d{2}):(\\d{2})(?:[.,](\\d+))?(?:Z|([+-])(\\d{2}):(\\d{2}))");

    /**
     * Go {@code time.Parse(time.RFC3339, s)} (checked against go1.26): upper-case T and Z, a {@code .} or
     * {@code ,} fraction of any length, no leap second, a zone offset up to 24:60 (hour 0-24, minute 0-60,
     * applied arithmetically). The one parser behind VC dates, DID document {@code revoked}, and DidResolver.
     */
    public static Instant parse(String s) throws DateTimeParseException {
        java.util.regex.Matcher m = STRICT.matcher(s == null ? "" : s);
        if (!m.matches()) {
            throw new DateTimeParseException("not RFC 3339 (upper-case T/Z, seconds, HH:MM offset)", String.valueOf(s), 0);
        }
        try {
            int offset = 0;
            if (m.group(8) != null) {
                int oh = Integer.parseInt(m.group(9));
                int om = Integer.parseInt(m.group(10));
                if (oh > 24 || om > 60) {
                    throw new DateTimeParseException("time zone offset out of range", s, 0);
                }
                offset = (oh * 3600 + om * 60) * ("-".equals(m.group(8)) ? -1 : 1);
            }
            String frac = m.group(7) == null ? "" : (m.group(7) + "000000000").substring(0, 9);
            int nanos = frac.isEmpty() ? 0 : Integer.parseInt(frac);
            return java.time.LocalDateTime.of(Integer.parseInt(m.group(1)), Integer.parseInt(m.group(2)),
                    Integer.parseInt(m.group(3)), Integer.parseInt(m.group(4)), Integer.parseInt(m.group(5)),
                    Integer.parseInt(m.group(6)), nanos).toInstant(ZoneOffset.UTC).minusSeconds(offset);
        } catch (java.time.DateTimeException e) {
            throw new DateTimeParseException(e.getMessage(), s, 0);
        }
    }
}
