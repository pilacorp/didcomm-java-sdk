package com.pila.credential.common.processor;

import com.apicatalog.jsonld.JsonLdError;
import com.pila.credential.common.processor.JsonLdLimitException.Kind;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static com.pila.credential.common.processor.JsonLdTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/** Port of go-credential-sdk document_loader_test.go (go #165). */
class DocumentLoaderTest {

    private static final Duration DEFAULT_TIMEOUT = RemoteContextLoader.fetchTimeout;

    @AfterEach
    void restore() {
        RemoteContextLoader.setHttpClient(null);
        RemoteContextLoader.fetchTimeout = DEFAULT_TIMEOUT;
    }

    private static JsonLdLimitException loadFailure(String url) {
        return assertThrows(JsonLdLimitException.class, () -> RemoteContextLoader.current().load(url));
    }

    private static void assertKind(Kind kind, JsonLdTestSupport.Entry entry, Map<String, Object> doc) {
        Exception e = assertThrows(Exception.class, () -> entry.run(doc));
        assertTrue(JsonLdLimitException.has(e, kind), "expected " + kind + ", got " + e);
    }

    @Test
    void concurrentCustomContexts() throws Exception {
        try (Server srv = new Server(ex -> writeContext(ex, "term")).useTestClient()) {
            AtomicReference<Throwable> failure = new AtomicReference<>();
            Thread[] ts = new Thread[8];
            for (int g = 0; g < ts.length; g++) {
                int gg = g;
                ts[g] = new Thread(() -> {
                    try {
                        for (int i = 0; i < 25; i++) {
                            // Half the URLs are shared, so cached documents are read in parallel too.
                            String url = srv.url + (i % 2 == 0 ? "/" + gg + "-" + i : "/" + i);
                            String got = new String(Processor.canonicalizeDocument(docUsing(url, "term")));
                            assertTrue(got.contains("https://example.org/term"), "term not expanded: " + got);
                        }
                    } catch (Throwable t) {
                        failure.compareAndSet(null, t);
                    }
                });
                ts[g].start();
            }
            for (Thread t : ts) t.join();
            assertNull(failure.get(), String.valueOf(failure.get()));
        }
    }

    @Test
    void slowFetchBlocksNothingElse() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch started = new CountDownLatch(1);
        try (Server srv = new Server(ex -> {
            if (ex.getRequestURI().getPath().equals("/slow")) {
                started.countDown();
                try {
                    release.await(20, TimeUnit.SECONDS);
                } catch (InterruptedException ignored) {
                    // test over
                }
            }
            writeContext(ex, "term");
        }).useTestClient()) {
            RemoteContextLoader.current().load(srv.url + "/cached");
            Thread slow = new Thread(() -> {
                try {
                    RemoteContextLoader.current().load(srv.url + "/slow");
                } catch (JsonLdLimitException ignored) {
                    // released at the end
                }
            });
            slow.setDaemon(true);
            slow.start();
            assertTrue(started.await(5, TimeUnit.SECONDS));
            long start = System.nanoTime();
            RemoteContextLoader.current().load(srv.url + "/cached");
            RemoteContextLoader.current().load(srv.url + "/other");
            assertTrue((System.nanoTime() - start) / 1_000_000_000 < 5, "a slow fetch held up another load");
            release.countDown();
        }
    }

    @Test
    void cachesAFetchOnce() throws Exception {
        AtomicInteger hits = new AtomicInteger();
        try (Server srv = new Server(ex -> {
            hits.incrementAndGet();
            writeContext(ex, "term");
        }).useTestClient()) {
            for (int i = 0; i < 3; i++) RemoteContextLoader.current().load(srv.url);
            assertEquals(1, hits.get());
        }
    }

    @Test
    void cacheIsBounded() throws Exception {
        try (Server srv = new Server(ex -> writeContext(ex, "term"))) {
            RemoteContextLoader loader = new RemoteContextLoader(HttpClient.newHttpClient());
            assertTrue((long) RemoteContextLoader.MAX_CACHED_CONTEXTS * RemoteContextLoader.MAX_CONTEXT_BYTES <= 64L << 20);
            for (int i = 0; i < RemoteContextLoader.MAX_CACHED_CONTEXTS; i++) loader.load(srv.url + "/" + i);
            assertEquals(RemoteContextLoader.MAX_CACHED_CONTEXTS, loader.docs.size());
            loader.load(srv.url + "/" + RemoteContextLoader.MAX_CACHED_CONTEXTS);
            assertEquals(RemoteContextLoader.MAX_CACHED_CONTEXTS, loader.docs.size());
        }
    }

    /** The cache holds the fetched bytes, not a decoded tree. */
    @Test
    void cacheHoldsBytes() throws Exception {
        String body = "{\"@context\":{\"<a>\":\"https://example.org/é&\"},\"x\":[" + "{},".repeat(1000) + "{}]}";
        try (Server srv = new Server(ex -> respond(ex, 200, "application/ld+json", body)).useTestClient()) {
            RemoteContextLoader.Fetched first = RemoteContextLoader.current().load(srv.url);
            RemoteContextLoader.Fetched second = RemoteContextLoader.current().load(srv.url);
            assertEquals(body.getBytes(java.nio.charset.StandardCharsets.UTF_8).length, first.raw().length);
            assertArrayEquals(first.raw(), second.raw());
        }
    }

    @Test
    void defaultClientRefusesLoopback() throws Exception {
        AtomicInteger hits = new AtomicInteger();
        String closedUrl;
        try (Server closed = new Server(ex -> respond(ex, 404, null, ""))) {
            closedUrl = closed.url;
        }
        try (Server srv = new Server(ex -> {
            hits.incrementAndGet();
            writeContext(ex, "term");
        })) {
            int port = srv.http.getAddress().getPort();
            List<String> messages = new java.util.ArrayList<>();
            // localhost goes through DNS: the refusal has to come after resolution.
            for (String url : List.of(srv.url, "http://localhost:" + port, closedUrl)) {
                Exception e = assertThrows(Exception.class, () -> Processor.canonicalizeDocument(docUsing(url, "term")), url);
                assertTrue(JsonLdLimitException.has(e, Kind.ADDRESS), url + ": " + e);
                messages.add(String.valueOf(e.getMessage()).replace(url, "URL"));
            }
            assertEquals(0, hits.get(), "the server was reached");
            // An answering port and a closed one must read the same.
            assertEquals(messages.get(0), messages.get(2));
            for (String leak : List.of("refused", "dial", "status", "not public")) {
                assertFalse(messages.get(0).contains(leak), "error text reveals " + leak + ": " + messages.get(0));
            }
        }
    }

    @Test
    void isPublicAddr() throws Exception {
        Map<String, Boolean> cases = new java.util.LinkedHashMap<>();
        cases.put("8.8.8.8", true);
        cases.put("1.1.1.1", true);
        cases.put("2606:4700:4700::1111", true);
        cases.put("127.0.0.1", false);
        cases.put("0.0.0.0", false);
        cases.put("10.0.0.1", false);
        cases.put("100.64.0.1", false);
        cases.put("100.100.100.200", false); // Alibaba metadata
        cases.put("169.254.169.254", false); // AWS, GCP, Azure metadata
        cases.put("172.16.0.1", false);
        cases.put("192.168.1.1", false);
        cases.put("198.18.0.1", false);
        cases.put("224.0.0.1", false);
        cases.put("255.255.255.255", false);
        cases.put("::", false);
        cases.put("::1", false);
        cases.put("fe80::1", false);
        cases.put("fc00::1", false);
        cases.put("fd00:ec2::254", false); // AWS metadata over IPv6
        cases.put("ff02::1", false);
        cases.put("::ffff:127.0.0.1", false);
        cases.put("::ffff:169.254.169.254", false);
        cases.put("::169.254.169.254", false);
        cases.put("64:ff9b::a9fe:a9fe", false); // NAT64 of 169.254.169.254
        cases.put("2002:a9fe:a9fe::", false);   // 6to4 of 169.254.169.254
        for (Map.Entry<String, Boolean> c : cases.entrySet()) {
            assertEquals(c.getValue(), RemoteContextLoader.isPublic(InetAddress.getByName(c.getKey())), c.getKey());
        }
        // An address without a host must be refused.
        JsonLdLimitException e = assertThrows(JsonLdLimitException.class, () -> RemoteContextLoader.refuseNonPublic(URI.create("http://:443/")));
        assertEquals(Kind.ADDRESS, e.kind());
    }

    @Test
    void refusesOtherSchemes() throws Exception {
        java.nio.file.Path file = java.nio.file.Files.createTempFile("context", ".json");
        java.nio.file.Files.writeString(file, "{\"@context\":{}}");
        try {
            for (String url : List.of(file.toString(), "file://" + file, "ftp://example.org/context")) {
                assertTrue(JsonLdLimitException.has(loadFailure(url), Kind.SCHEME), url);
            }
        } finally {
            java.nio.file.Files.delete(file);
        }
        // A file offered as an alternate: a name with a scheme reads as a path.
        try (Server srv = new Server(ex -> {
            ex.getResponseHeaders().set("Link", "<ftp:context.json>; rel=\"alternate\"; type=\"application/ld+json\"");
            respond(ex, 200, "text/html", "");
        }).useTestClient()) {
            assertTrue(JsonLdLimitException.has(loadFailure(srv.url), Kind.SCHEME), "alternate");
        }
    }

    @Test
    void refusesOversizedResponse() throws Exception {
        try (Server srv = new Server(ex -> {
            int pad = RemoteContextLoader.MAX_CONTEXT_BYTES - 100;
            if (ex.getRequestURI().getPath().equals("/over")) pad = RemoteContextLoader.MAX_CONTEXT_BYTES + 100;
            respond(ex, 200, "application/ld+json", "{\"@context\":{\"pad\":\"" + "x".repeat(pad) + "\"}}");
        }).useTestClient()) {
            assertDoesNotThrow(() -> RemoteContextLoader.current().load(srv.url + "/under"), "a context under the limit must load");
            loadFailure(srv.url + "/over");
        }
    }

    @Test
    void timesOut() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        try (Server srv = new Server(ex -> {
            ex.sendResponseHeaders(200, 0);
            ex.getResponseBody().write("{\"@context\":".getBytes()); // headers and part of a body, then a stall
            ex.getResponseBody().flush();
            try {
                release.await(20, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {
                // test over
            }
            ex.close();
        }).useTestClient()) {
            RemoteContextLoader.fetchTimeout = Duration.ofMillis(300);
            long start = System.nanoTime();
            JsonLdLimitException e = loadFailure(srv.url);
            assertTrue((System.nanoTime() - start) / 1_000_000_000 < 5, "took too long");
            assertTrue(hasCause(e, java.util.concurrent.TimeoutException.class), String.valueOf(e.getCause()));
            release.countDown();
        }
    }

    private static boolean hasCause(Throwable t, Class<? extends Throwable> type) {
        for (int i = 0; t != null && i < 64; i++, t = t.getCause()) if (type.isInstance(t)) return true;
        return false;
    }

    /** The library-style recursion on rel=alternate runs past a client's redirect limit; the loader counts every hop. */
    @Test
    void boundsAlternateChain() throws Exception {
        AtomicInteger hits = new AtomicInteger();
        try (Server srv = new Server(ex -> {
            ex.getResponseHeaders().set("Link", "</" + hits.incrementAndGet() + ">; rel=\"alternate\"; type=\"application/ld+json\"");
            respond(ex, 200, "text/html", "");
        }).useTestClient()) {
            assertTrue(JsonLdLimitException.has(loadFailure(srv.url), Kind.REQUESTS));
            assertEquals(RemoteContextLoader.MAX_CONTEXT_REQUESTS, hits.get());
        }
    }

    /** A context that names itself must end in an error, not a stack overflow. */
    @Test
    void contextIncludingItself() throws Exception {
        try (Server srv = new Server(ex -> respond(ex, 200, "application/ld+json",
                "{\"@context\":\"http://" + ex.getRequestHeaders().getFirst("Host") + "/\"}")).useTestClient()) {
            Map<String, Object> doc = docUsing(srv.url + "/", "term");
            assertThrows(Exception.class, () -> Processor.canonicalizeDocument(doc));
            assertThrows(Exception.class, () -> Processor.canonicalizeForSd(doc));
            assertThrows(Exception.class, () -> Processor.toRdfNQuads(doc));
        }
    }

    @Test
    void budgetStopsAtDeadline() throws Exception {
        ContextBudget budget = new ContextBudget();
        budget.deadline = System.nanoTime() - 1_000_000_000L;
        JsonLdError e = assertThrows(JsonLdError.class, () -> budget.loadDocument(URI.create("https://example.org/context"), null));
        assertTrue(JsonLdLimitException.has(e, Kind.OVERFLOW), String.valueOf(e));
        assertNotNull(budget.loadDocument(URI.create("https://www.w3.org/ns/credentials/v2"), null), "a bundled context needs no budget");
    }

    @Test
    void customContextLoadsThroughHookOnly() throws Exception {
        AtomicInteger hits = new AtomicInteger();
        try (Server srv = new Server(ex -> {
            switch (ex.getRequestURI().getPath()) {
                case "/context" -> {
                    hits.incrementAndGet();
                    writeContext(ex, "term");
                }
                // How schema.org answers: a page pointing at its context, behind a redirect.
                case "/redirect" -> {
                    ex.getResponseHeaders().set("Location", "/page");
                    respond(ex, 302, null, "");
                }
                default -> {
                    ex.getResponseHeaders().set("Link", "</context>; rel=\"alternate\"; type=\"application/ld+json\"");
                    respond(ex, 200, "text/html", "");
                }
            }
        }).useTestClient()) {
            for (String path : List.of("/context", "/redirect")) {
                String got = new String(Processor.canonicalizeForSd(docUsing(srv.url + path, "term")));
                assertTrue(got.contains("<https://example.org/term> \"value\""), path + ": term not expanded: " + got);
            }
            RemoteContextLoader.setHttpClient(null);
            hits.set(0);
            assertThrows(Exception.class, () -> Processor.canonicalizeForSd(docUsing(srv.url + "/context", "term")),
                    "without the hook the same URL must be refused, cached or not");
            assertEquals(0, hits.get(), "the server was reached");
        }
    }

    /** A log wants the cause and a caller must not see it: the text stays one, the chain holds what went wrong. */
    @Test
    void causeIsOnTheChainOnly() throws Exception {
        try (Server srv = new Server(ex -> {
            switch (ex.getRequestURI().getPath()) {
                case "/big" -> respond(ex, 200, "application/ld+json", "{\"@context\":{\"pad\":\"" + "x".repeat(RemoteContextLoader.MAX_CONTEXT_BYTES) + "\"}}");
                case "/notjson" -> respond(ex, 200, "application/ld+json", "<html>");
                default -> respond(ex, 500, null, "");
            }
        }).useTestClient()) {
            JsonLdLimitException big = loadFailure(srv.url + "/big");
            assertEquals(Kind.LOAD, big.kind());
            assertInstanceOf(IOException.class, big.getCause(), "the cause is gone");
            for (String path : List.of("/notjson", "/500")) {
                assertEquals(big.getMessage(), loadFailure(srv.url + path).getMessage(), path + " reads differently");
            }
        }
    }

    /** A caller tells the failures apart through the library's wrapping. */
    @Test
    void contextErrorsAreReachable() throws Exception {
        try (Server loopback = new Server(ex -> writeContext(ex, "term"))) {
            Exception e = assertThrows(Exception.class, () -> Processor.canonicalizeDocument(docUsing(loopback.url, "term")));
            assertTrue(JsonLdLimitException.has(e, Kind.ADDRESS) && JsonLdLimitException.has(e, Kind.LOAD), "address: " + e);
        }
        assertKind(Kind.SCHEME, Processor::canonicalizeForSd, docUsing("ftp://example.org/context", "term"));
        try (Server srv = new Server(ex -> {
            ex.getResponseHeaders().set("Link", "<ftp:context.json>; rel=\"alternate\"; type=\"application/ld+json\"");
            respond(ex, 200, "text/html", "");
        }).useTestClient()) {
            assertKind(Kind.SCHEME, Processor::canonicalizeForSd, docUsing(srv.url, "term"));
        }
        AtomicInteger hits = new AtomicInteger();
        try (Server srv = new Server(ex -> {
            ex.getResponseHeaders().set("Link", "</" + hits.incrementAndGet() + ">; rel=\"alternate\"; type=\"application/ld+json\"");
            respond(ex, 200, "text/html", "");
        }).useTestClient()) {
            assertKind(Kind.REQUESTS, Processor::canonicalizeForSd, docUsing(srv.url, "term"));
        }
        CountDownLatch release = new CountDownLatch(1);
        try (Server srv = new Server(ex -> {
            try {
                release.await(20, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {
                // test over
            }
            ex.close();
        }).useTestClient()) {
            RemoteContextLoader.fetchTimeout = Duration.ofMillis(100);
            Exception e = assertThrows(Exception.class, () -> Processor.canonicalizeForSd(docUsing(srv.url, "term")));
            assertTrue(hasCause(e, java.net.http.HttpTimeoutException.class) || hasCause(e, java.util.concurrent.TimeoutException.class), "deadline: " + e);
            release.countDown();
        }
    }

    /** One operation may parse MAX_CONTEXT_BYTES_PER_OPERATION and no more. Bundled contexts count. */
    @Test
    void budgetBytesPerOperation() throws Exception {
        try (Server srv = new Server(ex -> writeContext(ex, "term")).useTestClient()) {
            int remote = RemoteContextLoader.current().load(srv.url).raw().length;
            String bundledUrl = "https://www.w3.org/ns/credentials/v2";
            int bundled = LocalContextDocumentLoader.localBytes(URI.create(bundledUrl)).length;
            Map<String, Object[]> cases = new java.util.LinkedHashMap<>();
            cases.put("remote", new Object[]{srv.url, remote});
            cases.put("bundled", new Object[]{bundledUrl, bundled});
            for (Map.Entry<String, Object[]> c : cases.entrySet()) {
                URI url = URI.create((String) c.getValue()[0]);
                long size = (Integer) c.getValue()[1];
                ContextBudget budget = new ContextBudget();
                budget.bytes = ContextBudget.MAX_CONTEXT_BYTES_PER_OPERATION - size;
                assertDoesNotThrow(() -> budget.loadDocument(url, null), c.getKey() + " at the limit");
                ContextBudget over = new ContextBudget();
                over.bytes = ContextBudget.MAX_CONTEXT_BYTES_PER_OPERATION - size + 1;
                JsonLdError e = assertThrows(JsonLdError.class, () -> over.loadDocument(url, null), c.getKey());
                assertTrue(JsonLdLimitException.has(e, Kind.OVERFLOW), c.getKey() + ": " + e);
            }
        }
    }

    @Test
    void loadCountIsBounded() throws Exception {
        try (Server srv = new Server(ex -> writeContext(ex, "term")).useTestClient()) {
            ContextBudget budget = new ContextBudget();
            budget.loads = ContextBudget.MAX_CONTEXT_LOADS;
            JsonLdError e = assertThrows(JsonLdError.class, () -> budget.loadDocument(URI.create(srv.url), null));
            assertTrue(JsonLdLimitException.has(e, Kind.OVERFLOW));
        }
    }

    @Test
    void unparsableAlternateIsRefused() throws Exception {
        try (Server srv = new Server(ex -> {
            ex.getResponseHeaders().set("Link", "<%zz>; rel=\"alternate\"; type=\"application/ld+json\"");
            writeContext(ex, "term");
        }).useTestClient()) {
            assertTrue(JsonLdLimitException.has(loadFailure(srv.url), Kind.SCHEME));
            assertKind(Kind.SCHEME, Processor::toRdfNQuads, docUsing(srv.url, "term"));
        }
    }

    /** Runtime failures from the JSON-LD library become clean errors on every entry point. */
    @Test
    void malformedContextIsACleanError() {
        Map<String, Object> doc = m("@context", List.of(m("@base", "http://example.org/", "p", "https://example.org/p"), "%zz"),
                "@id", "urn:x", "p", "v");
        termEntries().forEach((fn, entry) -> assertThrows(Exception.class, () -> entry.run(doc), fn));
    }

    @Test
    void guardTurnsRuntimeFailuresIntoErrors() {
        Exception e = assertThrows(Exception.class, () -> JsonLdLimits.guard("op", () -> {
            throw new ClassCastException("boom");
        }));
        assertTrue(e.getMessage().contains("malformed JSON-LD input"), e.getMessage());
        assertThrows(Exception.class, () -> JsonLdLimits.guard("op", () -> {
            throw new StackOverflowError();
        }));
    }
}
