package com.pila.credential.common.processor;

import com.apicatalog.jsonld.JsonLd;
import com.apicatalog.rdf.api.RdfQuadConsumer;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.function.IntFunction;

/** Shared helpers for the ports of go-credential-sdk's processor hardening tests. */
final class JsonLdTestSupport {

    private JsonLdTestSupport() {
    }

    interface Entry {
        void run(Map<String, Object> doc) throws Exception;
    }

    static Map<String, Object> m(Object... kv) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) out.put((String) kv[i], kv[i + 1]);
        return out;
    }

    static final Map<String, Object> LINK_CONTEXT = m(
            "knows", m("@id", "https://example.org/knows", "@type", "@id"),
            "name", "https://example.org/name");

    static Map<String, Object> graphOf(int nodes, IntFunction<List<Integer>> targets) {
        List<Object> graph = new ArrayList<>();
        for (int i = 0; i < nodes; i++) {
            List<Object> links = new ArrayList<>();
            for (int j : targets.apply(i)) links.add(m("@id", "_:n" + j));
            graph.add(m("@id", "_:n" + i, "knows", links));
        }
        return m("@context", LINK_CONTEXT, "@graph", graph);
    }

    /** The attack: every node links to every other. */
    static Map<String, Object> blankClique(int nodes) {
        return graphOf(nodes, i -> {
            List<Integer> others = new ArrayList<>();
            for (int j = 0; j < nodes; j++) if (j != i) others.add(j);
            return others;
        });
    }

    static Map<String, Object> blankCycle(int nodes) {
        return graphOf(nodes, i -> List.of((i + 1) % nodes));
    }

    static List<Object> repeated(String value, int times) {
        List<Object> l = new ArrayList<>();
        for (int i = 0; i < times; i++) l.add(value);
        return l;
    }

    /** Go's canonicalizers(): every canonicalizing entry point. */
    static Map<String, Entry> canonicalizers() {
        Map<String, Entry> e = new LinkedHashMap<>();
        e.put("canonicalizeDocument", Processor::canonicalizeDocument);
        e.put("canonicalizeForSd", Processor::canonicalizeForSd);
        e.put("canonicalizeWithIdMap", Processor::canonicalizeWithIdMap);
        e.put("canonicalizeNQuadsWithIdMap", d -> Processor.canonicalizeNQuadsWithIdMap(Processor.toRdfNQuads(d)));
        return e;
    }

    static Map<String, Entry> termEntries() {
        Map<String, Entry> e = canonicalizers();
        e.put("expandJsonLd", Processor::expandJsonLd);
        e.put("toRdfNQuads", Processor::toRdfNQuads);
        return e;
    }

    /** The quads json-ld produces for doc, as the blank-node cap sees them. */
    static List<JsonLdLimits.Quad> quadsOf(Map<String, Object> doc) throws Exception {
        List<JsonLdLimits.Quad> quads = new ArrayList<>();
        JsonLd.toRdf(JsonLdSdProcessor.toDocument(doc)).options(JsonLdSdProcessor.sdOptions()).provide(new RdfQuadConsumer() {
            @Override
            public RdfQuadConsumer quad(String s, String p, String o, String dt, String l, String d, String g) {
                quads.add(new JsonLdLimits.Quad(s, p, o, dt, l, d, g));
                return this;
            }
        });
        return quads;
    }

    static Map<String, Object> docUsing(String contextUrl, String term) {
        return m("@context", contextUrl, "@id", "https://example.org/subject", term, "value");
    }

    static Map<String, Object> docWithContext(Object ctx, String term) {
        return m("@context", ctx, "@id", "https://example.org/subject", term, "value");
    }

    /** A loopback server; its client skips the public-address check like Go's httptest client. */
    static final class Server implements AutoCloseable {
        final HttpServer http;
        final String url;

        Server(HttpHandler handler) throws IOException {
            http = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
            http.createContext("/", handler);
            http.setExecutor(Executors.newCachedThreadPool(r -> {
                Thread t = new Thread(r);
                t.setDaemon(true);
                return t;
            }));
            http.start();
            url = "http://127.0.0.1:" + http.getAddress().getPort();
        }

        /** Route the process-wide loader through a plain client (no address check) until close. */
        Server useTestClient() {
            RemoteContextLoader.setHttpClient(HttpClient.newHttpClient());
            return this;
        }

        @Override
        public void close() {
            RemoteContextLoader.setHttpClient(null);
            http.stop(0);
        }
    }

    static void respond(HttpExchange ex, int status, String contentType, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        if (contentType != null) ex.getResponseHeaders().set("Content-Type", contentType);
        ex.sendResponseHeaders(status, b.length == 0 ? -1 : b.length);
        if (b.length > 0) ex.getResponseBody().write(b);
        ex.close();
    }

    static void writeContext(HttpExchange ex, String term) throws IOException {
        respond(ex, 200, "application/ld+json", "{\"@context\":{\"" + term + "\":\"https://example.org/" + term + "\"}}");
    }

    static Map<String, Object> hashMap() {
        return new HashMap<>();
    }
}
