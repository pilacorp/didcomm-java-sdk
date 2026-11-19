package com.pila.credential.common.schema;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Port of Go's {@code net/mail.ParseAddress} (go1.26, {@code message.go}) reduced to "does it parse":
 * addr-spec, name-addr with a phrase, trailing comment, a one-address group, domain literals (IP only),
 * quoted strings and RFC 2047 words (only the charsets Go decodes itself are accepted).
 */
final class GoMail {
    private static final Pattern ENCODED_WORD = Pattern.compile("^=\\?([^?\\s]+)\\?([qQbB])\\?([^?\\s]*)\\?=$");
    private static final class Fail extends Exception {
        Fail() {
            super(null, null, false, false);
        }
    }

    private String s;

    private GoMail(String s) {
        this.s = s;
    }

    static boolean parses(String address) {
        try {
            return new GoMail(address).parseSingleAddress();
        } catch (Fail e) {
            return false;
        }
    }

    private boolean parseSingleAddress() throws Fail {
        int n = parseAddress(true);
        if (!skipCFWS()) throw new Fail();
        if (!s.isEmpty()) throw new Fail(); // expected single address
        if (n != 1) throw new Fail(); // empty group, or a group with several addresses
        return true;
    }

    /** Returns how many addresses it consumed (a group may hold any number). */
    private int parseAddress(boolean handleGroup) throws Fail {
        skipSpace();
        if (s.isEmpty()) throw new Fail();
        boolean addrSpec;
        try {
            consumeAddrSpec(); // restores s on failure
            addrSpec = true;
        } catch (Fail notAddrSpec) {
            addrSpec = false;
        }
        if (addrSpec) { // a bad comment after a good addr-spec fails the parse; it does not fall back to name-addr
            skipSpace();
            if (!s.isEmpty() && s.charAt(0) == '(') consumeDisplayNameComment();
            return 1;
        }

        if (s.charAt(0) != '<') consumePhrase();
        skipSpace();
        if (handleGroup && consume(':')) return consumeGroupList();
        if (!consume('<')) throw new Fail();
        consumeAddrSpec();
        if (!consume('>')) throw new Fail();
        return 1;
    }

    private int consumeGroupList() throws Fail {
        int count = 0;
        skipSpace();
        if (consume(';')) {
            if (!skipCFWS()) throw new Fail();
            return 0;
        }
        while (true) {
            skipSpace();
            count += parseAddress(false);
            if (!skipCFWS()) throw new Fail();
            if (consume(';')) {
                if (!skipCFWS()) throw new Fail();
                break;
            }
            if (!consume(',')) throw new Fail();
        }
        return count;
    }

    private void consumeAddrSpec() throws Fail {
        String orig = s;
        try {
            skipSpace();
            if (s.isEmpty()) throw new Fail();
            if (s.charAt(0) == '"') {
                if (consumeQuotedString().isEmpty()) throw new Fail();
            } else {
                consumeAtom(true, false);
            }
            if (!consume('@')) throw new Fail();
            skipSpace();
            if (s.isEmpty()) throw new Fail();
            if (s.charAt(0) == '[') consumeDomainLiteral();
            else consumeAtom(true, false);
        } catch (Fail e) {
            s = orig;
            throw e;
        }
    }

    private void consumePhrase() throws Fail {
        List<String> words = new ArrayList<>();
        boolean prevEncoded = false;
        Fail err = null;
        while (true) {
            if (!words.isEmpty() && !skipCFWS()) throw new Fail();
            skipSpace();
            if (s.isEmpty()) break;
            boolean encoded = false;
            try {
                String word;
                if (s.charAt(0) == '"') {
                    word = consumeQuotedString();
                } else {
                    word = consumeAtom(true, true);
                    encoded = decodeRfc2047Word(word);
                }
                if (prevEncoded && encoded) words.set(words.size() - 1, words.get(words.size() - 1) + word);
                else words.add(word);
                prevEncoded = encoded;
            } catch (Fail e) {
                err = e;
                break;
            }
        }
        if (err != null && words.isEmpty()) throw err;
    }

    /** @return whether the word is RFC 2047 encoded; throws when Go would (charset it cannot decode). */
    private boolean decodeRfc2047Word(String word) throws Fail {
        var m = ENCODED_WORD.matcher(word);
        if (!m.matches()) return false;
        String cs = m.group(1).toLowerCase(java.util.Locale.ROOT);
        if (!cs.equals("utf-8") && !cs.equals("iso-8859-1") && !cs.equals("us-ascii")) throw new Fail();
        String text = m.group(3);
        if (m.group(2).equalsIgnoreCase("b")) {
            try {
                java.util.Base64.getDecoder().decode(text);
            } catch (IllegalArgumentException e) {
                return false; // errInvalidWord: read as an ordinary word
            }
        } else if (!text.matches("(?:[^=]|=[0-9A-Fa-f]{2})*")) {
            return false;
        }
        return true;
    }

    private String consumeQuotedString() throws Fail {
        int i = 1;
        StringBuilder qs = new StringBuilder();
        boolean escaped = false;
        while (true) {
            if (i >= s.length()) throw new Fail(); // unclosed quoted-string
            int r = s.codePointAt(i);
            int size = Character.charCount(r);
            if (escaped) {
                if (!isVchar(r) && !isWsp(r)) throw new Fail();
                qs.appendCodePoint(r);
                escaped = false;
            } else if (isQtext(r) || isWsp(r)) {
                qs.appendCodePoint(r);
            } else if (r == '"') {
                break;
            } else if (r == '\\') {
                escaped = true;
            } else {
                throw new Fail();
            }
            i += size;
        }
        s = s.substring(i + 1);
        return qs.toString();
    }

    private String consumeAtom(boolean dot, boolean permissive) throws Fail {
        int i = 0;
        while (i < s.length()) {
            int r = s.codePointAt(i);
            if (!isAtext(r, dot)) break;
            i += Character.charCount(r);
        }
        if (i == 0) throw new Fail();
        String atom = s.substring(0, i);
        s = s.substring(i);
        if (!permissive && (atom.startsWith(".") || atom.contains("..") || atom.endsWith("."))) throw new Fail();
        return atom;
    }

    private void consumeDomainLiteral() throws Fail {
        if (!consume('[')) throw new Fail();
        int len = 0;
        String dtext = s;
        while (true) {
            if (s.isEmpty()) throw new Fail();
            if (s.charAt(0) == ']') break;
            int r = s.codePointAt(0);
            if (!isDtext(r)) throw new Fail();
            int size = Character.charCount(r);
            len += size;
            s = s.substring(size);
        }
        dtext = dtext.substring(0, len);
        if (!consume(']')) throw new Fail();
        if (!FormatChecks.isFormat(dtext.indexOf(':') >= 0 ? "ipv6" : "ipv4", dtext)) throw new Fail(); // net.ParseIP
    }

    private void consumeDisplayNameComment() throws Fail {
        if (!consume('(')) throw new Fail();
        String comment = consumeComment();
        if (comment == null) throw new Fail();
        for (String w : comment.split("[ \t]+")) {
            if (!w.isEmpty()) decodeRfc2047Word(w);
        }
    }

    private boolean skipCFWS() {
        skipSpace();
        while (consume('(')) {
            if (consumeComment() == null) return false;
            skipSpace();
        }
        return true;
    }

    /** @return the comment text, or null when it is not closed. */
    private String consumeComment() {
        int depth = 1;
        StringBuilder comment = new StringBuilder();
        while (!s.isEmpty() && depth != 0) {
            char c = s.charAt(0);
            if (c == '\\' && s.length() > 1) s = s.substring(1);
            else if (c == '(') depth++;
            else if (c == ')') depth--;
            if (depth > 0) comment.append(s.charAt(0));
            s = s.substring(1);
        }
        return depth == 0 ? comment.toString() : null;
    }

    private boolean consume(char c) {
        if (s.isEmpty() || s.charAt(0) != c) return false;
        s = s.substring(1);
        return true;
    }

    private void skipSpace() {
        int i = 0;
        while (i < s.length() && (s.charAt(i) == ' ' || s.charAt(i) == '\t')) i++;
        s = s.substring(i);
    }

    private static boolean isAtext(int r, boolean dot) {
        if (r == '.') return dot;
        if ("()<>[]:;@\\,\"".indexOf(r) >= 0) return false;
        return isVchar(r);
    }

    private static boolean isQtext(int r) {
        return r != '\\' && r != '"' && isVchar(r);
    }

    private static boolean isVchar(int r) {
        return ('!' <= r && r <= '~') || r >= 0x80;
    }

    private static boolean isWsp(int r) {
        return r == ' ' || r == '\t';
    }

    private static boolean isDtext(int r) {
        return r != '[' && r != ']' && r != '\\' && isVchar(r);
    }
}
