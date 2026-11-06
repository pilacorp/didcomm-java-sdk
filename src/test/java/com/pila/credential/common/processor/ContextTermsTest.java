package com.pila.credential.common.processor;

import com.pila.credential.common.processor.JsonLdLimitException.Kind;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static com.pila.credential.common.processor.ContextBudget.MAX_CONTEXT_TERMS;
import static com.pila.credential.common.processor.ContextBudget.MAX_CONTEXT_TERM_BYTES;
import static com.pila.credential.common.processor.ContextBudget.MAX_INLINE_CONTEXT_TERMS;
import static com.pila.credential.common.processor.JsonLdTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/** Port of go-credential-sdk context_terms_test.go (go #165). */
class ContextTermsTest {

    private static Map<String, Object> inlineTerms(int n) {
        Map<String, Object> ctx = new LinkedHashMap<>();
        for (int i = 0; i < n; i++) ctx.put("t" + i, "https://example.org/vocab#t" + i);
        return ctx;
    }

    /** t0 and then `links` terms, each the one before plus a suffix, so `links` terms of `value` bytes are in use as prefixes. */
    private static Map<String, Object> prefixChain(int links, int value) {
        Map<String, Object> ctx = new LinkedHashMap<>();
        ctx.put("t0", "https://example.org/");
        for (int i = 1; i <= links; i++) {
            String name = "t" + (i - 1);
            ctx.put("t" + i, name + ":" + "x".repeat(value - name.length() - 2) + "/");
        }
        ctx.put("last", "t" + links + ":last");
        return ctx;
    }

    private static void assertKind(Kind kind, JsonLdTestSupport.Entry entry, Map<String, Object> doc) {
        Exception e = assertThrows(Exception.class, () -> entry.run(doc));
        assertTrue(JsonLdLimitException.has(e, kind), "expected " + kind + ", got " + e);
    }

    @Test
    void inlineLimit() {
        termEntries().forEach((fn, entry) -> {
            assertDoesNotThrow(() -> entry.run(docWithContext(inlineTerms(MAX_INLINE_CONTEXT_TERMS), "t0")), fn + " at the limit");
            assertKind(Kind.TOO_MANY_TERMS, entry, docWithContext(inlineTerms(MAX_INLINE_CONTEXT_TERMS + 1), "t0"));
        });
    }

    /** Contexts inside the document count wherever they are, as do scoped ones and the nested form. */
    @Test
    void inlineCountReachesEveryContext() {
        Map<String, Object> over = inlineTerms(MAX_INLINE_CONTEXT_TERMS + 1);
        Map<String, Map<String, Object>> docs = new LinkedHashMap<>();
        docs.put("node", m("@context", m("knows", "https://example.org/knows"),
                "knows", List.of(m("@context", over, "t0", "value"))));
        docs.put("array", m("@context", List.of(inlineTerms(1), over), "t0", "value"));
        docs.put("nested", m("@context", List.of(m("@context", over)), "t0", "value"));
        docs.put("scoped", m("@context", m("t0", m("@id", "https://example.org/t0", "@context", over)), "t0", "value"));
        docs.forEach((name, doc) -> assertKind(Kind.TOO_MANY_TERMS, Processor::expandJsonLd, doc));
    }

    private static String remoteContext(int n) {
        StringBuilder b = new StringBuilder("{\"@context\":{\"t0\":\"https://example.org/t0\"");
        for (int i = 1; i < n; i++) b.append(",\"t").append(i).append("\":\"https://example.org/t").append(i).append('"');
        return b.append("}}").toString();
    }

    @Test
    void remoteLimit() throws Exception {
        try (Server srv = new Server(ex -> respond(ex, 200, "application/ld+json",
                remoteContext(ex.getRequestURI().getPath().equals("/at") ? MAX_CONTEXT_TERMS : MAX_CONTEXT_TERMS + 1))).useTestClient()) {
            assertDoesNotThrow(() -> Processor.canonicalizeDocument(docUsing(srv.url + "/at", "t0")), "at the limit");
            assertKind(Kind.TOO_MANY_TERMS, Processor::canonicalizeDocument, docUsing(srv.url + "/past", "t0"));
        }
    }

    /** A context named many times is many parses of the same terms, not more terms. */
    @Test
    void repeatedContextCountsOnce() throws Exception {
        try (Server srv = new Server(ex -> respond(ex, 200, "application/ld+json", remoteContext(MAX_CONTEXT_TERMS / 2))).useTestClient()) {
            Map<String, Object> knows = m("knows", "https://example.org/knows");
            Map<String, Object> doc = docUsing(srv.url, "t0");
            doc.put("knows", m("@context", List.of(srv.url, knows), "t0", "value"));
            doc.put("@context", List.of(srv.url, knows));
            assertDoesNotThrow(() -> Processor.canonicalizeForSd(doc));
        }
    }

    @Test
    void lengthLimit() {
        java.util.function.IntFunction<String> lng = n -> "https://example.org/" + "x".repeat(n - "https://example.org/".length());
        Map<String, java.util.function.IntFunction<Map<String, Object>>> shapes = new LinkedHashMap<>();
        shapes.put("term IRI", n -> docWithContext(m("term", lng.apply(n)), "term"));
        shapes.put("term @id", n -> docWithContext(m("term", m("@id", lng.apply(n))), "term"));
        shapes.put("term name", n -> {
            String name = "x".repeat(n);
            return docWithContext(m("@vocab", "https://example.org/", name, "https://example.org/term"), name);
        });
        shapes.put("@vocab", n -> docWithContext(m("@vocab", lng.apply(n)), "term"));
        shapes.put("@base", n -> m("@context", m("@base", lng.apply(n), "term", "https://example.org/term"),
                "@id", "https://example.org/subject", "term", "value"));
        shapes.forEach((name, doc) -> {
            assertDoesNotThrow(() -> Processor.canonicalizeForSd(doc.apply(MAX_CONTEXT_TERM_BYTES)), name + " at the limit");
            assertKind(Kind.TERM_TOO_LONG, Processor::canonicalizeForSd, doc.apply(MAX_CONTEXT_TERM_BYTES + 1));
        });
    }

    /** What a chain adds to an IRI is bounded however it is spread over terms. */
    @Test
    void chainLimit() {
        int value = 100;
        int links = MAX_CONTEXT_TERM_BYTES / value;
        int spare = MAX_CONTEXT_TERM_BYTES % value;

        Map<String, Object> at = prefixChain(links, value);
        at.put("t0", "urn:" + "x".repeat(spare - 6) + ":/");
        // A root with no // is a link of the chain too, and so is every suffix.
        assertDoesNotThrow(() -> Processor.canonicalizeForSd(docWithContext(at, "last")), "at the limit");
        Map<String, Object> past = prefixChain(links, value);
        past.put("t0", "urn:" + "x".repeat(spare - 5) + ":/");
        assertKind(Kind.TERM_TOO_LONG, Processor::canonicalizeForSd, docWithContext(past, "last"));
    }

    /** Every way the library joins two strings into an IRI has to count. */
    @Test
    void chainShapes() {
        String suffix = "x".repeat(1000) + "/";
        List<Object> vocabChain = new ArrayList<>(List.of(m("@vocab", "https://example.org/")));
        for (int i = 0; i < 4; i++) vocabChain.add(m("@vocab", suffix));
        Map<String, Object> aliases = m("t0", "https://example.org/");
        for (int i = 1; i < 4; i++) {
            // a0 is t0 under another name, so the chain never names t0 as a prefix.
            aliases.put("a" + (i - 1), "t" + (i - 1));
            aliases.put("t" + i, "a" + (i - 1) + ":" + suffix);
        }
        aliases.put("last", "t3:last");
        List<Object> twoNames = List.of(
                m("a", "https://example.org/", "b", "a:" + suffix),
                m("a", "b:" + suffix),
                m("b", "a:" + suffix),
                m("a", "b:" + suffix, "last", "a:last"));
        List<Object> compactNames = new ArrayList<>(List.of(m("t0", "https://example.org/")));
        for (int i = 1; i < 4; i++) compactNames.add(m("@vocab", "t" + (i - 1) + ":" + suffix, "t" + i, m()));

        Map<String, Object> ctxs = m("@vocab", vocabChain, "aliases", aliases, "two names", twoNames, "compact names", compactNames);
        ctxs.forEach((name, ctx) -> assertKind(Kind.TERM_TOO_LONG, Processor::expandJsonLd, docWithContext(ctx, "last")));
    }

    /** A chain that crosses from the document into a remote context and back is one chain. */
    @Test
    void chainCrossesInlineAndRemote() throws Exception {
        String suffix = "x".repeat(1000) + "/";
        try (Server srv = new Server(ex -> respond(ex, 200, "application/ld+json",
                "{\"@context\":{\"t1\":\"t0:" + suffix + "\",\"t3\":\"t2:" + suffix + "\"}}")).useTestClient()) {
            List<Object> ctx = List.of(
                    m("t0", "https://example.org/"),
                    srv.url,
                    m("t2", "t1:" + suffix, "t4", "t3:" + suffix, "last", "t4:last"));
            assertKind(Kind.TERM_TOO_LONG, Processor::expandJsonLd, docWithContext(ctx, "last"));
        }
    }

    /** What real contexts look like must pass with room: many terms over a few prefixes, and aliases. */
    @Test
    void acceptsRealShapes() {
        Map<String, Object> ctx = m("schema", "https://schema.org/", "xsd", "http://www.w3.org/2001/XMLSchema#",
                "ex", "urn:example:", "id", "@id", "type", "@type");
        for (int i = 0, n = MAX_INLINE_CONTEXT_TERMS - ctx.size() - 2; i < n; i++) {
            ctx.put("t" + i, m("@id", "schema:t" + i, "@type", "xsd:string"));
        }
        ctx.put("alias", "t0");
        ctx.put("self", "self");
        ctx.put("@vocab", "https://example.org/vocab#");
        assertDoesNotThrow(() -> Processor.canonicalizeForSd(docWithContext(ctx, "alias")));
    }
}
