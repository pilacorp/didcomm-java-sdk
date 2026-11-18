package com.pila.credential.common.schema;

import java.util.regex.Pattern;

import com.pila.credential.common.util.Rfc3339;

/**
 * The {@code format} checkers of gojsonschema v1.2.0 ({@code format_checkers.go}): 17 formats, strings and
 * numbers only, unknown formats pass. Go's parsers ({@code net/mail}, {@code net/url}, {@code net.ParseIP},
 * {@code time.Parse}) are reproduced by hand for the accepted shapes; see FormatChecksTest for the table
 * measured against Go.
 */
final class FormatChecks {
    private static final Pattern HOSTNAME = Pattern.compile(
            "^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])(\\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9]))*$");
    private static final Pattern UUID = Pattern.compile("^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$");
    private static final Pattern JSON_POINTER = Pattern.compile("^(?:/(?:[^~/]|~0|~1)*)*$");
    private static final Pattern REL_JSON_POINTER = Pattern.compile("^(?:0|[1-9][0-9]*)(?:#|(?:/(?:[^~/]|~0|~1)*)*)$");
    private static final Pattern DATE = Pattern.compile("(\\d{4})-(\\d{2})-(\\d{2})");
    private static final Pattern CLOCK = Pattern.compile(
            "(\\d{2}):(\\d{2}):(\\d{2})(?:[.,]\\d+)?(Z|[+-]\\d{2}:\\d{2})?");
    private static final String ATEXT = "[A-Za-z0-9!#$%&'*+/=?^_`{|}~\\-\\u0080-\\uffff]";
    private static final Pattern DOT_ATOM = Pattern.compile(ATEXT + "+(?:\\." + ATEXT + "+)*");
    private static final Pattern QUOTED = Pattern.compile("\"(?:[^\"\\\\\\r\\n]|\\\\.)*\"");
    private static final Pattern DOMAIN_LITERAL = Pattern.compile("\\[[^\\[\\]\\\\\\r\\n]*]");
    private static final Pattern PHRASE_WORD = Pattern.compile(
            "(?:\"(?:[^\"\\\\\\r\\n]|\\\\.)*\"|" + ATEXT + "+(?:\\." + ATEXT + "*)*)");

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
            case "idn-email": return s != null && email(s);
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
        String scheme = urlParse(s);
        return scheme != null && !s.contains("\\") && (!schemeRequired || !scheme.isEmpty());
    }

    /** Returns the scheme ("" when none) if Go's url.Parse accepts s, else null. */
    private static String urlParse(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x20 || c == 0x7f) return null;
        }
        String rest = s;
        int hash = rest.indexOf('#');
        if (hash >= 0) {
            if (!validPercent(rest.substring(hash + 1))) return null;
            rest = rest.substring(0, hash);
        }
        String scheme = "";
        for (int i = 0; i < rest.length(); i++) {
            char c = rest.charAt(i);
            if (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') continue;
            if (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.') {
                if (i == 0) break;
                continue;
            }
            if (c == ':') {
                if (i == 0) return null;
                scheme = rest.substring(0, i);
                rest = rest.substring(i + 1);
            }
            break;
        }
        int q = rest.indexOf('?');
        if (q >= 0) rest = rest.substring(0, q);
        if (scheme.isEmpty() && !rest.startsWith("/")) {
            int colon = rest.indexOf(':');
            if (colon >= 0 && (rest.indexOf('/') < 0 || colon < rest.indexOf('/'))) return null;
        }
        String path = rest;
        if (rest.startsWith("//")) {
            int slash = rest.indexOf('/', 2);
            String authority = slash >= 0 ? rest.substring(2, slash) : rest.substring(2);
            path = slash >= 0 ? rest.substring(slash) : "";
            if (!validAuthority(authority)) return null;
        }
        return validPercent(path) ? scheme : null;
    }

    private static boolean validAuthority(String a) {
        int at = a.lastIndexOf('@');
        if (at >= 0) {
            String user = a.substring(0, at);
            if (!validPercent(user)) return false;
            a = a.substring(at + 1);
        }
        String host = a;
        if (a.startsWith("[")) {
            int close = a.indexOf(']');
            if (close < 0) return false;
            String port = a.substring(close + 1);
            return (port.isEmpty() || port.matches(":\\d*")) && ipv6(a.substring(1, close).replaceAll("%25.*$", ""));
        }
        int colon = a.lastIndexOf(':');
        if (colon >= 0) {
            if (!a.substring(colon).matches(":\\d*")) return false;
            host = a.substring(0, colon);
        }
        for (int i = 0; i < host.length(); i++) {
            char c = host.charAt(i);
            if (c == '%') {
                if (!validPercent(host.substring(i, Math.min(i + 3, host.length())))) return false;
            } else if (c == ' ' || c == '"' || c == '<' || c == '>' || c == '\\' || c == '^' || c == '`'
                    || c == '{' || c == '|' || c == '}') {
                return false;
            }
        }
        return true;
    }

    private static boolean validPercent(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '%') {
                if (i + 2 >= s.length() || Character.digit(s.charAt(i + 1), 16) < 0
                        || Character.digit(s.charAt(i + 2), 16) < 0) {
                    return false;
                }
            }
        }
        return true;
    }

    private static boolean uriTemplate(String s) {
        if (urlParse(s) == null || s.contains("\\")) return false;
        // ^([^{]*({[^}]*})?)*$ on the path: a '{' opens a group that runs to the next '}' (nested '{' allowed).
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '{') {
                i = s.indexOf('}', i);
                if (i < 0) return false;
            }
        }
        return true;
    }

    private static boolean regex(String s) {
        if (s.isEmpty()) return true;
        try {
            Pattern.compile(s);
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }

    // ---- net/mail.ParseAddress ----

    private static boolean email(String s) {
        s = s.strip();
        if (s.isEmpty()) return false;
        if (s.endsWith(">")) {
            int lt = s.lastIndexOf('<');
            if (lt < 0) return false;
            String phrase = s.substring(0, lt).strip();
            if (!phrase.isEmpty() && !phrase(phrase)) return false;
            return addrSpec(s.substring(lt + 1, s.length() - 1).strip());
        }
        return addrSpec(s);
    }

    private static boolean phrase(String p) {
        for (String w : p.split("\\s+")) {
            if (!PHRASE_WORD.matcher(w).matches()) return false;
        }
        return true;
    }

    private static boolean addrSpec(String a) {
        int at = a.lastIndexOf('@');
        if (at <= 0 || at == a.length() - 1) return false;
        String local = a.substring(0, at);
        String domain = a.substring(at + 1);
        boolean localOk = DOT_ATOM.matcher(local).matches() || QUOTED.matcher(local).matches();
        return localOk && (DOT_ATOM.matcher(domain).matches() || DOMAIN_LITERAL.matcher(domain).matches());
    }
}
