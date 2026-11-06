package com.pila.credential.common.processor;

import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.JsonLdErrorCode;
import com.apicatalog.jsonld.JsonLdOptions;
import com.apicatalog.jsonld.document.Document;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.jsonld.loader.DocumentLoaderOptions;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.processor.JsonLdLimitException.Kind;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The document loader of ONE JSON-LD operation (never share it): bounds the context loads, time and
 * bytes of the operation and holds its term definitions (go-credential-sdk contextBudget).
 * Bundled contexts include no remote context and spend only bytes.
 */
final class ContextBudget implements DocumentLoader {

    /** Remote context loads of one operation, cached ones included. */
    static final int MAX_CONTEXT_LOADS = 1024;
    static final long MAX_CONTEXT_LOAD_NANOS = 30_000_000_000L;
    /** Context bytes one operation parses. */
    static final long MAX_CONTEXT_BYTES_PER_OPERATION = 4L << 20;
    /** Distinct terms of an operation (schema.org has ~3,000). */
    static final int MAX_CONTEXT_TERMS = 10000;
    /** Terms in the document itself. */
    static final int MAX_INLINE_CONTEXT_TERMS = 1000;
    /** A term's name, IRI, @vocab, @base, and the bytes of all definitions other terms expand through. */
    static final int MAX_CONTEXT_TERM_BYTES = 1 << 10;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    int loads;
    long bytes;
    long deadline = System.nanoTime() + MAX_CONTEXT_LOAD_NANOS;
    final ContextTerms terms = new ContextTerms();

    @Override
    public Document loadDocument(URI url, DocumentLoaderOptions options) throws JsonLdError {
        byte[] local = LocalContextDocumentLoader.localBytes(url);
        if (local != null) {
            if ((bytes += local.length) > MAX_CONTEXT_BYTES_PER_OPERATION) throw overflow();
            return LocalContextDocumentLoader.documentOf(url, local);
        }
        if (++loads > MAX_CONTEXT_LOADS || System.nanoTime() - deadline > 0) throw overflow();
        try {
            RemoteContextLoader.Fetched f = RemoteContextLoader.current().load(url.toString());
            if ((bytes += f.raw().length) > MAX_CONTEXT_BYTES_PER_OPERATION) throw overflow();
            terms.addDocument(MAPPER.readValue(f.raw(), Object.class));
            terms.check(MAX_CONTEXT_TERMS);
            return LocalContextDocumentLoader.documentOf(f.documentUrl(), f.raw());
        } catch (JsonLdLimitException e) {
            throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED, e.getMessage(), e);
        } catch (java.io.IOException e) {
            throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED, "remote context could not be loaded", e);
        }
    }

    private static JsonLdError overflow() {
        String msg = "the operation's context budget is used up";
        return new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED, msg, new JsonLdLimitException(Kind.OVERFLOW, msg));
    }

    /** Options for one operation, with its own budget. */
    static JsonLdOptions newOptions() {
        return new JsonLdOptions(new ContextBudget());
    }

    /**
     * Puts doc's own contexts on the operation's budget before the library processes them. It must be
     * the budget's, not a count of their own: a chain can alternate between the document and remote contexts.
     */
    static void limitInlineContexts(JsonLdOptions opts, Object doc) throws JsonLdLimitException {
        ContextTerms t = ((ContextBudget) opts.getDocumentLoader()).terms;
        t.addDocument(doc);
        t.check(MAX_INLINE_CONTEXT_TERMS);
    }

    /**
     * Sizes the term definitions of an operation before the library processes them. Which definition
     * wins depends on context order, so this ignores order and counts every definition of every term
     * another one expands through: an IRI can use each of those at most once.
     */
    static final class ContextTerms {
        final Map<String, List<String>> defs = new HashMap<>(); // a term's IRIs as written
        final Set<String> used = new HashSet<>();                // terms other terms expand through
        long chain;                                              // bytes of the definitions of those
        long longest;                                            // longest name or IRI as written

        void check(int limit) throws JsonLdLimitException {
            if (defs.size() > limit) {
                throw new JsonLdLimitException(Kind.TOO_MANY_TERMS, "too many context term definitions: limit is " + limit);
            }
            if (longest > MAX_CONTEXT_TERM_BYTES || chain > MAX_CONTEXT_TERM_BYTES) {
                throw new JsonLdLimitException(Kind.TERM_TOO_LONG, "context term is too long: limit is " + MAX_CONTEXT_TERM_BYTES + " bytes");
            }
        }

        /** Adds the @context values anywhere under v. */
        void addDocument(Object v) {
            if (v instanceof List<?> l) {
                for (Object item : l) addDocument(item);
            } else if (v instanceof Map<?, ?> m) {
                for (Map.Entry<?, ?> e : m.entrySet()) {
                    if ("@context".equals(String.valueOf(e.getKey()))) add(e.getValue());
                    else addDocument(e.getValue());
                }
            }
        }

        /** A string in a context is a remote one, which comes back through ContextBudget when loaded. */
        private void add(Object ctx) {
            if (ctx instanceof List<?> l) {
                for (Object item : l) add(item);
            } else if (ctx instanceof Map<?, ?> m) {
                for (Map.Entry<?, ?> e : m.entrySet()) {
                    String key = String.valueOf(e.getKey());
                    Object def = e.getValue();
                    if (key.equals("@context")) {
                        add(def);
                    } else if (key.equals("@vocab") || key.equals("@base")) {
                        if (def instanceof String iri) {
                            longest = Math.max(longest, len(iri));
                            link(iri);
                        }
                    } else if (!key.startsWith("@")) {
                        define(key, def);
                    }
                }
            }
        }

        private void define(String term, Object def) {
            String iri = term; // with no IRI of its own a term is its name, joined to @vocab or a prefix
            if (def instanceof String s) {
                iri = s;
            } else if (def instanceof Map<?, ?> d) {
                if (d.get("@id") instanceof String id) iri = id;
                else if (d.get("@reverse") instanceof String r) iri = r;
                add(d.get("@context"));
            }
            longest = Math.max(longest, Math.max(len(term), len(iri)));
            defs.computeIfAbsent(term, k -> new ArrayList<>()).add(iri);
            if (used.contains(term)) link(iri);
            if (iri.contains(":")) use(expandsThrough(iri));
        }

        private void use(String term) {
            if (!used.add(term)) return;
            for (String iri : new ArrayList<>(defs.getOrDefault(term, List.of()))) link(iri);
        }

        /** Counts an IRI that part of a chain is written as. */
        private void link(String iri) {
            String term = expandsThrough(iri);
            if (!term.isEmpty()) {
                chain += len(iri);
                use(term);
            }
        }

        /**
         * The term the library may expand iri through: the part before the colon of a compact IRI, or
         * all of an alias. "" for what it takes as it stands: a keyword, a blank node, or scheme://.
         */
        static String expandsThrough(String iri) {
            int colon = iri.indexOf(':');
            String prefix = colon < 0 ? iri : iri.substring(0, colon);
            String suffix = colon < 0 ? "" : iri.substring(colon + 1);
            if (iri.startsWith("@") || prefix.equals("_") || suffix.startsWith("//")) return "";
            return prefix;
        }

        private static int len(String s) {
            return s.getBytes(StandardCharsets.UTF_8).length;
        }
    }
}
