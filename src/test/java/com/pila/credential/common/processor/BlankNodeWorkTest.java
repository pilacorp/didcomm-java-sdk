package com.pila.credential.common.processor;

import com.pila.credential.common.processor.JsonLdLimitException.Kind;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.pila.credential.common.processor.JsonLdTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/** Port of go-credential-sdk canonicalize_blanknode_test.go (go #165). */
class BlankNodeWorkTest {

    private static void assertRefused(Entry entry, Map<String, Object> doc, long maxMillis) {
        long start = System.nanoTime();
        Exception e = assertThrows(Exception.class, () -> entry.run(doc));
        assertTrue(JsonLdLimitException.has(e, Kind.BLANK_NODE_WORK), "expected a refusal, got " + e);
        assertTrue((System.nanoTime() - start) / 1_000_000 < maxMillis, "refusal was slow");
    }

    @Test
    void refusesExpensiveBlankNodes() {
        Map<String, Map<String, Object>> docs = Map.of(
                "clique of 9", blankClique(9),
                "clique of 40", blankClique(40),
                "cycle of 1000", blankCycle(1000));
        docs.forEach((name, doc) -> canonicalizers().forEach((fn, entry) -> {
            try {
                assertRefused(entry, doc, 5000);
            } catch (AssertionError e) {
                throw new AssertionError(name + "/" + fn + ": " + e.getMessage(), e);
            }
        }));
    }

    /** What the cap must let through: nodes that differ in data cost nothing; interchangeable proofs are the one real repeat. */
    @Test
    void acceptsCredentialShapes() {
        List<Object> anonymous = new ArrayList<>();
        List<Object> identical = new ArrayList<>();
        for (int i = 0; i < 300; i++) {
            anonymous.add(m("name", "course " + i));
            identical.add(m("name", "same"));
        }
        java.util.function.BiFunction<String, String, Map<String, Object>> proof = (graph, id) ->
                m("@id", graph, "@graph", List.of(m("@id", id, "name", "same proof")));
        Map<String, Map<String, Object>> docs = new java.util.LinkedHashMap<>();
        docs.put("300 anonymous objects", m("@context", LINK_CONTEXT, "knows", anonymous));
        docs.put("300 identical objects", m("@context", LINK_CONTEXT, "knows", identical));
        docs.put("interchangeable proofs", m("@context", LINK_CONTEXT, "@graph", List.of(proof.apply("_:g1", "_:p1"), proof.apply("_:g2", "_:p2"))));
        docs.put("list of one value", m("@context", m("values", m("@id", "https://example.org/values", "@container", "@list")),
                "values", repeated("x", 60)));
        docs.forEach((name, doc) -> canonicalizers().forEach((fn, entry) ->
                assertDoesNotThrow(() -> entry.run(doc), name + "/" + fn)));
    }

    /** A clique just inside the score must stay cheap: the limit bounds the time. */
    @Test
    void limitIsCheap() throws Exception {
        long work = JsonLdLimits.blankNodeWork(quadsOf(blankClique(3)));
        assertTrue(work > 0 && work <= JsonLdLimits.MAX_BLANK_NODE_WORK, "clique of 3 scored " + work);
        long start = System.nanoTime();
        assertDoesNotThrow(() -> Processor.canonicalizeForSd(blankClique(3)));
        assertTrue((System.nanoTime() - start) / 1_000_000 < 5000);
    }

    /** The legacy canonicalizer keeps its lenient semantics: an undefined term is silently dropped, not rejected. */
    @Test
    void legacyCanonicalizeDocumentStaysLenient() throws Exception {
        Map<String, Object> doc = m("@context", m("name", "https://example.org/name"),
                "@id", "https://example.org/s", "name", "kept", "undefinedTerm", "dropped");
        String out = new String(Processor.canonicalizeDocument(doc), java.nio.charset.StandardCharsets.UTF_8);
        assertTrue(out.contains("\"kept\""), out);
        assertFalse(out.contains("dropped"), out);
        assertThrows(Exception.class, () -> Processor.canonicalizeForSd(doc)); // SafeMode path rejects it
    }

    /** The guard runs on every document before the signature check, so it must not be the cost itself. */
    @Test
    void blankNodeWorkIsCheapOnWideNodes() throws Exception {
        List<Object> children = new ArrayList<>();
        for (int i = 0; i < 5000; i++) children.add(m("name", "same"));
        Map<String, Object> doc = m("@context", LINK_CONTEXT, "knows", m("knows", children));
        List<JsonLdLimits.Quad> quads = quadsOf(doc);
        long start = System.nanoTime();
        assertEquals(0, JsonLdLimits.blankNodeWork(quads));
        assertTrue((System.nanoTime() - start) / 1_000_000 < 5000);
    }

    /** 100 nodes of 96 predicates scored exactly the old limit and took 7 s in Go. */
    @Test
    void refusesManyEdges() {
        List<Object> nodes = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            Map<String, Object> node = m("@id", "_:b" + i);
            for (int p = 0; p < 96; p++) node.put("p" + p, m("@id", "_:b" + ((i + p + 1) % 100)));
            nodes.add(node);
        }
        Map<String, Object> doc = m("@context", m("@vocab", "https://example.org/"), "@graph", nodes);
        assertRefused(Processor::canonicalizeForSd, doc, 10000);
    }

    /** A list of one repeated value is the real document nearest the limit. */
    @Test
    void blankNodeWorkLimit() throws Exception {
        java.util.function.IntFunction<Map<String, Object>> list = n -> m(
                "@context", m("values", m("@id", "https://example.org/values", "@container", "@list")),
                "values", repeated("x", n));
        assertEquals(JsonLdLimits.MAX_BLANK_NODE_WORK, JsonLdLimits.blankNodeWork(quadsOf(list.apply(102))), "a list of 102");
        assertDoesNotThrow(() -> Processor.canonicalizeForSd(list.apply(102)), "at the limit");
        Exception e = assertThrows(Exception.class, () -> Processor.canonicalizeForSd(list.apply(103)));
        assertTrue(JsonLdLimitException.has(e, Kind.BLANK_NODE_WORK), "one past the limit: " + e);
    }

    /** Nodes with nothing to order cost one pass, whatever their edges. */
    @Test
    void ignoresGroupsWithNoSearch() throws Exception {
        List<Object> children = new ArrayList<>();
        for (int i = 0; i < 2000; i++) children.add(m("name", "same", "knows", m("name", String.valueOf(i))));
        Map<String, Object> doc = m("@context", LINK_CONTEXT, "knows", m("knows", children));
        assertEquals(0, JsonLdLimits.blankNodeWork(quadsOf(doc)));
    }
}
