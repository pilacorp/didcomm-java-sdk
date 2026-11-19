package com.pila.credential.common.processor;

import com.apicatalog.rdf.api.RdfQuadConsumer;
import com.apicatalog.rdf.canon.RdfCanon;
import com.apicatalog.rdf.canon.RdfCanonTimeTicker;
import com.pila.credential.common.processor.JsonLdLimitException.Kind;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Blank-node work cap before URDNA2015, and the clean-error guard (go canonicalize_idmap.go, processor.go). */
final class JsonLdLimits {

    /**
     * Admits every document in this SDK's tests (score 0, or 8 per pair of interchangeable proofs, and a
     * list of 102 equal values) and refuses anything shaped like the known attacks (a clique of 4 scores 46656).
     * A cap on the number of blank nodes cannot do this.
     */
    static final int MAX_BLANK_NODE_WORK = 20000;

    private JsonLdLimits() {
    }

    interface Op<T> {
        T run() throws Exception;
    }

    interface RdfSource {
        void provideTo(RdfQuadConsumer consumer) throws Exception;
    }

    /**
     * Go's recoverJSONLD: a runtime failure inside the JSON-LD library on adversarial input (including
     * stack exhaustion) becomes a clean error. Declared refusals and checked errors pass through.
     */
    static <T> T guard(String op, Op<T> body) throws Exception {
        try {
            return body.run();
        } catch (RuntimeException | StackOverflowError e) {
            throw new Exception(op + ": malformed JSON-LD input: " + e, e);
        }
    }

    record Quad(String s, String p, String o, String dt, String lang, String dir, String g) {
    }

    /**
     * The one path into URDNA2015: collects the quads, refuses a dataset that would take it factorial
     * time (Titanium, like json-gold, has only a wall-clock ticker), and replays them into a fresh RdfCanon.
     */
    static RdfCanon canon(RdfSource source) throws Exception {
        Set<Quad> quads = new LinkedHashSet<>();
        source.provideTo(new RdfQuadConsumer() {
            @Override
            public RdfQuadConsumer quad(String s, String p, String o, String dt, String lang, String dir, String g) {
                quads.add(new Quad(s, p, o, dt, lang, dir, g));
                return this;
            }
        });
        if (blankNodeWork(quads) > MAX_BLANK_NODE_WORK) {
            throw new JsonLdLimitException(Kind.BLANK_NODE_WORK, "normalize: too many interchangeable blank nodes");
        }
        RdfCanon canon = RdfCanon.create("SHA-256", new RdfCanonTimeTicker(5 * 1000));
        for (Quad q : quads) {
            canon.quad(q.s, q.p, q.o, q.dt, q.lang, q.dir, q.g);
        }
        return canon;
    }

    private record Relation(String how, String id) {
    }

    private static boolean blankSubject(String s) {
        return s != null && RdfQuadConsumer.isBlank(s);
    }

    private static boolean blankObject(Quad q) {
        return q.o != null && !RdfQuadConsumer.isLiteral(q.dt, q.lang, q.dir) && RdfQuadConsumer.isBlank(q.o);
    }

    /** Hash First Degree Quads rule: the node under test reads as _:a and every other blank node as _:z. */
    private static String masked(String node, boolean blank, String id) {
        if (!blank) return node;
        return node.equals(id) ? "_:a" : "_:z";
    }

    /**
     * Scores the search URDNA2015 will do (go blankNodeWork). A blank node whose quads, blank nodes
     * masked, match no other node's is labelled at once and costs nothing. The rest are interchangeable:
     * Hash N-Degree Quads tries every ordering of each list of related nodes and recurses into the
     * unlabelled ones. A group of interchangeable nodes joined by shared quads scores the product of
     * those orderings over its members, times its size, times its edges to blank nodes.
     */
    static long blankNodeWork(Iterable<Quad> quads) {
        Map<String, List<String>> lines = new LinkedHashMap<>();
        Map<String, List<Relation>> related = new HashMap<>();
        for (Quad q : quads) {
            String[] nodes = {q.s, q.o, q.g};
            boolean[] blank = {blankSubject(q.s), blankObject(q), blankSubject(q.g)};
            String objectKey = blank[1] ? q.o : q.o + "|" + q.dt + "|" + q.lang + "|" + q.dir;
            for (int n = 0; n < 3; n++) {
                if (!blank[n]) continue;
                String id = nodes[n];
                lines.computeIfAbsent(id, k -> new ArrayList<>()).add(
                        masked(q.s, blank[0], id) + " " + q.p + " "
                                + (blank[1] ? masked(q.o, true, id) : objectKey) + " "
                                + (q.g == null ? "" : masked(q.g, blank[2], id)));
                for (int i = 0; i < 3; i++) {
                    if (blank[i] && !nodes[i].equals(id)) {
                        // Hash Related Blank Node leaves the predicate out for a graph name.
                        String how = i < 2 ? i + q.p : "g";
                        related.computeIfAbsent(id, k -> new ArrayList<>()).add(new Relation(how, nodes[i]));
                    }
                }
            }
        }

        // Signatures are interned because a list key below copies one per relation.
        Map<String, Integer> signatures = new HashMap<>();
        Map<String, Integer> interned = new HashMap<>();
        Map<Integer, Integer> sharing = new HashMap<>();
        for (Map.Entry<String, List<String>> e : lines.entrySet()) {
            String sig = String.join("\n", sorted(e.getValue()));
            int n = interned.computeIfAbsent(sig, k -> interned.size());
            signatures.put(e.getKey(), n);
            sharing.merge(n, 1, Integer::sum);
        }

        long work = 0;
        Set<String> seen = new LinkedHashSet<>();
        for (String start : lines.keySet()) {
            if (seen.contains(start) || sharing.get(signatures.get(start)) <= 1) continue;
            seen.add(start);
            List<String> group = new ArrayList<>(List.of(start));
            long orderings = 1;
            long edges = 0;
            for (int i = 0; i < group.size(); i++) {
                List<Relation> rels = related.getOrDefault(group.get(i), List.of());
                edges += rels.size();
                // Lists can repeat a node, and the permutator then yields the distinct orderings:
                // the running multinomial of each list.
                Map<String, Integer> counts = new HashMap<>();
                for (Relation r : rels) {
                    String list = r.how + "\0" + signatures.get(r.id);
                    int inList = counts.merge(list, 1, Integer::sum);
                    int ofNode = counts.merge(list + "\0" + r.id, 1, Integer::sum);
                    orderings = orderings * inList / ofNode;
                    if (orderings > MAX_BLANK_NODE_WORK) return orderings;
                    if (!seen.contains(r.id) && sharing.get(signatures.get(r.id)) > 1) {
                        seen.add(r.id);
                        group.add(r.id);
                    }
                }
            }
            long search = orderings * group.size();
            if (search > 1) {
                work += search * edges;
                if (work > MAX_BLANK_NODE_WORK) return work;
            }
        }
        return work;
    }

    private static List<String> sorted(List<String> l) {
        List<String> c = new ArrayList<>(l);
        java.util.Collections.sort(c);
        return c;
    }
}
