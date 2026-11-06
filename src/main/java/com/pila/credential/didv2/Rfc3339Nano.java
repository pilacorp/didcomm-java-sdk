package com.pila.credential.didv2;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Go {@code time.Time} JSON text (RFC3339Nano: fraction trimmed of trailing zeros, the offset kept, "Z" for
 * UTC). A DID document's {@code revoked} is a Go {@code *time.Time}, so the document hash covers this
 * re-marshalled form, not the text it was parsed from.
 */
public final class Rfc3339Nano {
    // Go (checked against go1.26): 'T' and 'Z' upper case, a '.' or ',' fraction, a mandatory zone.
    private static final Pattern RFC3339 = Pattern.compile(
            "^(\\d{4})-(\\d{2})-(\\d{2})T(\\d{2}):(\\d{2}):(\\d{2})(?:[.,](\\d+))?(?:Z|([+-])(\\d{2}):(\\d{2}))$");

    private Rfc3339Nano() {
    }

    /** Parses strict RFC3339 and re-renders it as Go marshals a time.Time; throws on a malformed value. */
    public static String normalize(String text) throws Exception {
        if (text == null) {
            throw new Exception("parsing time \"null\" as RFC3339: malformed");
        }
        Matcher m = RFC3339.matcher(text);
        if (!m.matches()) {
            throw new Exception("parsing time \"" + text + "\" as \"2006-01-02T15:04:05Z07:00\": malformed");
        }
        try {
            LocalDateTime.of(Integer.parseInt(m.group(1)), Integer.parseInt(m.group(2)), Integer.parseInt(m.group(3)),
                    Integer.parseInt(m.group(4)), Integer.parseInt(m.group(5)), Integer.parseInt(m.group(6)));
        } catch (java.time.DateTimeException e) {
            throw new Exception("parsing time \"" + text + "\": " + e.getMessage(), e);
        }
        String zone = "Z";
        if (m.group(8) != null) {
            int zh = Integer.parseInt(m.group(9));
            int zm = Integer.parseInt(m.group(10));
            // Go accepts a minute offset of 60 (07:60 is +08:00) but not more, and cannot marshal 24h or more
            int total = zh * 3600 + zm * 60;
            if (zm > 60 || total >= 24 * 3600) {
                throw new Exception("parsing time \"" + text + "\": time zone offset out of range");
            }
            if (total != 0) {
                zone = m.group(8) + String.format("%02d:%02d", total / 3600, (total % 3600) / 60);
            }
        }
        String frac = m.group(7) == null ? "" : m.group(7);
        if (frac.length() > 9) {
            frac = frac.substring(0, 9);
        }
        frac = frac.replaceFirst("0+$", "");
        return m.group(1) + "-" + m.group(2) + "-" + m.group(3) + "T" + m.group(4) + ":" + m.group(5) + ":"
                + m.group(6) + (frac.isEmpty() ? "" : "." + frac) + zone;
    }

    /** Go time.Time.MarshalJSON for an instant in UTC. */
    public static String format(Instant at) {
        return format(at.atOffset(ZoneOffset.UTC));
    }

    /** Go time.Time.MarshalJSON, keeping the offset. */
    public static String format(OffsetDateTime at) {
        String s = String.format("%04d-%02d-%02dT%02d:%02d:%02d", at.getYear(), at.getMonthValue(),
                at.getDayOfMonth(), at.getHour(), at.getMinute(), at.getSecond());
        String frac = String.format("%09d", at.getNano()).replaceFirst("0+$", "");
        if (!frac.isEmpty()) {
            s += "." + frac;
        }
        int off = at.getOffset().getTotalSeconds();
        if (off == 0) {
            return s + "Z";
        }
        int abs = Math.abs(off);
        return s + (off < 0 ? "-" : "+") + String.format("%02d:%02d", abs / 3600, (abs % 3600) / 60);
    }
}
