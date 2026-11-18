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
    private static final java.util.regex.Pattern STRICT = java.util.regex.Pattern.compile(
            "\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[+-]\\d{2}:\\d{2})");

    public static Instant parse(String s) throws DateTimeParseException {
        if (!STRICT.matcher(s).matches()) {
            throw new DateTimeParseException("not RFC 3339 (upper-case T/Z, seconds, HH:MM offset)", s, 0);
        }
        return OffsetDateTime.parse(s, DateTimeFormatter.ISO_OFFSET_DATE_TIME).toInstant();
    }
}
