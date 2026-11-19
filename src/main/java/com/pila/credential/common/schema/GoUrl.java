package com.pila.credential.common.schema;

/**
 * Port of Go's {@code net/url.Parse} (go1.26, {@code url.go}) reduced to "does it parse" plus the pieces
 * gojsonschema reads: the scheme and the decoded path. Go works on bytes; here ASCII rules apply to chars below
 * 0x80 and every other char counts as a non-ASCII byte (allowed wherever Go allows bytes >= 0x80).
 */
final class GoUrl {
    /** scheme ("" when none), decoded path ("" for an opaque URL). */
    record Parsed(String scheme, String path) {
    }

    private GoUrl() {
    }

    /** @return null when Go's url.Parse returns an error. */
    static Parsed parse(String raw) {
        int hash = raw.indexOf('#');
        String u = hash >= 0 ? raw.substring(0, hash) : raw;
        Parsed p = parseNoFragment(u);
        if (p == null) return null;
        if (hash >= 0 && !validPercent(raw.substring(hash + 1))) return null; // unescape(frag, encodeFragment)
        return p;
    }

    private static Parsed parseNoFragment(String raw) {
        for (int i = 0; i < raw.length(); i++) {
            char b = raw.charAt(i);
            if (b < ' ' || b == 0x7f) return null; // invalid control character
        }
        if (raw.equals("*")) return new Parsed("", "*");

        String scheme = "";
        String rest = raw;
        scan:
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') continue;
            if (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.') {
                if (i == 0) break scan;
                continue;
            }
            if (c == ':') {
                if (i == 0) return null; // missing protocol scheme
                scheme = raw.substring(0, i).toLowerCase(java.util.Locale.ROOT);
                rest = raw.substring(i + 1);
            }
            break;
        }
        int q = rest.indexOf('?');
        if (q >= 0) rest = rest.substring(0, q);

        if (!rest.startsWith("/")) {
            if (!scheme.isEmpty()) return new Parsed(scheme, ""); // opaque
            int slash = rest.indexOf('/');
            String segment = slash >= 0 ? rest.substring(0, slash) : rest;
            if (segment.indexOf(':') >= 0) return null; // first path segment cannot contain colon
        }
        if ((!scheme.isEmpty() || !rest.startsWith("///")) && rest.startsWith("//")) {
            String authority = rest.substring(2);
            rest = "";
            int slash = authority.indexOf('/');
            if (slash >= 0) {
                rest = authority.substring(slash);
                authority = authority.substring(0, slash);
            }
            if (!parseAuthority(scheme, authority)) return null;
        }
        String path = unescapePath(rest);
        return path == null ? null : new Parsed(scheme, path);
    }

    private static boolean parseAuthority(String scheme, String authority) {
        int at = authority.lastIndexOf('@');
        if (!parseHost(at < 0 ? authority : authority.substring(at + 1))) return false;
        if (at < 0) return true;
        String userinfo = authority.substring(0, at);
        for (int i = 0; i < userinfo.length(); i++) {
            char r = userinfo.charAt(i);
            boolean ok = r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9'
                    || "-._:~!$&'()*+,;=%@".indexOf(r) >= 0;
            if (!ok) return false; // invalid userinfo (a non-ASCII char is not allowed here either)
        }
        return validPercent(userinfo);
    }

    private static boolean parseHost(String host) {
        int open = host.lastIndexOf('[');
        if (open != -1) {
            int close = host.lastIndexOf(']');
            if (close < 0) return false;
            String colonPort = host.substring(close + 1);
            if (!validOptionalPort(colonPort)) return false;
            String hostname = host.substring(open + 1, close);
            int zone = hostname.indexOf("%25");
            String addr;
            if (zone >= 0) {
                if (!validHostEscapes(hostname.substring(0, zone), false) || !validHostEscapes(hostname.substring(zone), true)) {
                    return false;
                }
                addr = hostname.substring(0, zone) + "%" + hostname.substring(zone + 3);
            } else {
                if (!validHostEscapes(hostname, false)) return false;
                addr = hostname;
            }
            // netip.ParseAddr: an IPv6 address with an optional non-empty zone; a plain IPv4 is "invalid IP-literal"
            int pct = addr.indexOf('%');
            String ip = pct >= 0 ? addr.substring(0, pct) : addr;
            if (pct >= 0 && pct == addr.length() - 1) return false;
            return ip.indexOf(':') >= 0 && FormatChecks.isFormat("ipv6", ip) && validHostEscapes(colonPort, false);
        }
        int colon = host.indexOf(':');
        if (colon != -1 && !validOptionalPort(host.substring(colon))) return false; // first colon: strict colons
        return validHostEscapes(host, false);
    }

    /** unescape(s, encodeHost / encodeZone): chars must be host-legal, %XX only for non-ASCII bytes (or %25). */
    private static boolean validHostEscapes(String s, boolean zone) {
        for (int i = 0; i < s.length(); ) {
            char c = s.charAt(i);
            if (c == '%') {
                if (i + 2 >= s.length() || !isHex(s.charAt(i + 1)) || !isHex(s.charAt(i + 2))) return false;
                int v = Character.digit(s.charAt(i + 1), 16) << 4 | Character.digit(s.charAt(i + 2), 16);
                boolean is25 = s.startsWith("%25", i);
                if (!zone && Character.digit(s.charAt(i + 1), 16) < 8 && !is25) return false;
                if (zone && !is25 && v != ' ' && hostShouldEscape((char) v)) return false;
                i += 3;
            } else {
                if (c < 0x80 && hostShouldEscape(c)) return false; // invalid character in host name
                i++;
            }
        }
        return true;
    }

    private static boolean hostShouldEscape(char c) {
        if (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') return false;
        return "!$&'()*+,;=:[]<>\"-_.~".indexOf(c) < 0;
    }

    private static boolean validOptionalPort(String port) {
        if (port.isEmpty()) return true;
        if (port.charAt(0) != ':') return false;
        for (int i = 1; i < port.length(); i++) {
            if (port.charAt(i) < '0' || port.charAt(i) > '9') return false;
        }
        return true;
    }

    private static boolean isHex(char c) {
        return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F';
    }

    /** %XX must be well formed; bytes are returned as chars (enough to look for '{' and '}'). */
    private static boolean validPercent(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '%') {
                if (i + 2 >= s.length() || !isHex(s.charAt(i + 1)) || !isHex(s.charAt(i + 2))) return false;
                i += 2;
            }
        }
        return true;
    }

    private static String unescapePath(String p) {
        if (!validPercent(p)) return null;
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < p.length(); i++) {
            char c = p.charAt(i);
            if (c == '%') {
                b.append((char) (Character.digit(p.charAt(i + 1), 16) << 4 | Character.digit(p.charAt(i + 2), 16)));
                i += 2;
            } else {
                b.append(c);
            }
        }
        return b.toString();
    }
}
