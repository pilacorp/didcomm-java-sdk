package com.pila.credential.common.util;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
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

    /** Strict parse (upper-case T/Z, numeric offsets allowed), like Go {@code time.Parse(time.RFC3339, s)}. */
    public static Instant parse(String s) throws DateTimeParseException {
        if (s.indexOf('t') >= 0 || s.indexOf('z') >= 0) {
            throw new DateTimeParseException("RFC 3339 requires upper-case T and Z", s, 0);
        }
        return OffsetDateTime.parse(s, DateTimeFormatter.ISO_OFFSET_DATE_TIME).toInstant();
    }
}
