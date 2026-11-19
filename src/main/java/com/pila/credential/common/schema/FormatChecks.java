package com.pila.credential.common.schema;

import java.util.regex.Pattern;

import com.pila.credential.common.util.Rfc3339;

/**
 * The {@code format} checkers of gojsonschema v1.2.0 ({@code format_checkers.go}): 17 formats, strings and
 * numbers only, unknown formats pass. {@link GoMail} and {@link GoUrl} port net/mail.ParseAddress and
 * net/url.Parse; FormatChecksTest compares everything against 10,000 inputs run through the real gojsonschema.
 */
final class FormatChecks {
    private static final Pattern HOSTNAME = Pattern.compile(
            "^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])(\\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9]))*$");
    private static final Pattern UUID = Pattern.compile("^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$");
    private static final Pattern JSON_POINTER = Pattern.compile("^(?:/(?:[^~/]|~0|~1)*)*$");
    private static final Pattern REL_JSON_POINTER = Pattern.compile("^(?:0|[1-9][0-9]*)(?:#|(?:/(?:[^~/]|~0|~1)*)*)$");
    private static final Pattern DATE = Pattern.compile("(\\d{4})-(\\d{2})-(\\d{2})");
    private static final Pattern CLOCK = Pattern.compile(
            "(\\d{1,2}):(\\d{2}):(\\d{2})(?:[.,]\\d+)?(Z|[+-]\\d{2}:\\d{2})?");

    private FormatChecks() {
    }

    /** @param s the value as a string, or null when the value is a number (every known format refuses it). */
    static boolean isFormat(String format, String s) {
        switch (format) {
            case "date": return s != null && date(s);
            case "time": return s != null && (clock(s, true) || clock(s, false));
            case "date-time": return s != null && (clock(s, true) || clock(s, false) || date(s) || rfc3339(s));
            case "hostname": return s != null && s.length() < 256 && HOSTNAME.matcher(s).matches();
            case "email":
            case "idn-email": return s != null && GoMail.parses(s);
            case "ipv4": return s != null && s.indexOf('.') >= 0 && ip(s);
            case "ipv6": return s != null && s.indexOf(':') >= 0 && ip(s);
            case "uri":
            case "iri": return s != null && uri(s, true);
            case "uri-reference":
            case "iri-reference": return s != null && uri(s, false);
            case "uri-template": return s != null && uriTemplate(s);
            case "uuid": return s != null && UUID.matcher(s).matches();
            case "regex": return s != null && regex(s);
            case "json-pointer": return s != null && JSON_POINTER.matcher(s).matches();
            case "relative-json-pointer": return s != null && REL_JSON_POINTER.matcher(s).matches();
            default: return true;
        }
    }

    private static boolean rfc3339(String s) {
        try {
            Rfc3339.parse(s);
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static boolean date(String s) {
        java.util.regex.Matcher m = DATE.matcher(s);
        if (!m.matches()) return false;
        try {
            java.time.LocalDate.of(Integer.parseInt(m.group(1)), Integer.parseInt(m.group(2)), Integer.parseInt(m.group(3)));
            return true;
        } catch (java.time.DateTimeException e) {
            return false;
        }
    }

    /** "15:04:05" (withZone=false) or "15:04:05Z07:00"; Go also takes a fraction after the seconds. */
    private static boolean clock(String s, boolean withZone) {
        java.util.regex.Matcher m = CLOCK.matcher(s);
        if (!m.matches() || (m.group(4) != null) != withZone) return false;
        if (Integer.parseInt(m.group(1)) > 23 || Integer.parseInt(m.group(2)) > 59 || Integer.parseInt(m.group(3)) > 59) {
            return false;
        }
        String z = m.group(4);
        return z == null || "Z".equals(z) || (Integer.parseInt(z.substring(1, 3)) <= 24 && Integer.parseInt(z.substring(4)) <= 60);
    }

    // ---- net.ParseIP ----

    private static boolean ip(String s) {
        return s.indexOf(':') >= 0 ? ipv6(s) : ipv4(s);
    }

    private static boolean ipv4(String s) {
        String[] p = s.split("\\.", -1);
        if (p.length != 4) return false;
        for (String x : p) {
            if (x.isEmpty() || x.length() > 3 || (x.length() > 1 && x.charAt(0) == '0')) return false;
            for (int i = 0; i < x.length(); i++) if (x.charAt(i) < '0' || x.charAt(i) > '9') return false;
            if (Integer.parseInt(x) > 255) return false;
        }
        return true;
    }

    private static boolean ipv6(String s) {
        if (s.indexOf('%') >= 0 || s.contains(":::")) return false;
        int dc = s.indexOf("::");
        if (dc >= 0 && s.indexOf("::", dc + 1) >= 0) return false;
        String head = dc >= 0 ? s.substring(0, dc) : s;
        String tail = dc >= 0 ? s.substring(dc + 2) : "";
        int groups = 0;
        for (String part : new String[] {head, tail}) {
            if (part.isEmpty()) continue;
            String[] g = part.split(":", -1);
            for (int i = 0; i < g.length; i++) {
                if (g[i].isEmpty()) return false;
                if (g[i].indexOf('.') >= 0) {
                    if (part != tail && dc >= 0 || i != g.length - 1 || !ipv4(g[i])) return false;
                    groups += 2;
                } else {
                    if (g[i].length() > 4 || !g[i].matches("[0-9a-fA-F]+")) return false;
                    groups++;
                }
            }
        }
        return dc >= 0 ? groups <= 7 : groups == 8;
    }

    // ---- net/url.Parse ----

    private static boolean uri(String s, boolean schemeRequired) {
        GoUrl.Parsed p = GoUrl.parse(s);
        return p != null && !s.contains("\\") && (!schemeRequired || !p.scheme().isEmpty());
    }

    /** url.Parse must succeed, and the decoded path must match {@code ^([^{]*({[^}]*})?)*$}. */
    private static boolean uriTemplate(String s) {
        GoUrl.Parsed p = GoUrl.parse(s);
        if (p == null || s.contains("\\")) return false;
        String path = p.path();
        // a '{' opens a group that runs to the next '}' (nested '{' allowed)
        for (int i = 0; i < path.length(); i++) {
            if (path.charAt(i) == '{') {
                i = path.indexOf('}', i);
                if (i < 0) return false;
            }
        }
        return true;
    }

    private static boolean regex(String s) {
        if (s.isEmpty()) return true;
        try {
            com.google.re2j.Pattern.compile(s); // Go: regexp.Compile (RE2)
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }
}
