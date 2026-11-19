package com.pila.credential.common.util;

import static org.junit.jupiter.api.Assertions.*;

import com.pila.credential.common.util.BoundedHttp.Failure;
import com.pila.credential.common.util.BoundedHttp.Kind;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/** S6': the request goes to the address that was checked, with a real HTTP/1.1 reader on top. */
class PinnedHttpTest {
    private static final long SEC = 1_000_000_000L;

    HttpServer server(java.util.function.Consumer<com.sun.net.httpserver.HttpExchange> h) throws Exception {
        HttpServer s = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        s.createContext("/", ex -> {
            h.accept(ex);
            ex.close();
        });
        s.start();
        return s;
    }

    static String read(BoundedHttp.Reply r) throws Exception {
        try (r) {
            return new String(r.body().readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @Test
    void readsContentLengthAndChunkedBodies() throws Exception {
        HttpServer s = server(ex -> {
            try {
                boolean chunked = ex.getRequestURI().getPath().equals("/chunked");
                ex.getResponseHeaders().add("X-A", "1");
                ex.sendResponseHeaders(200, chunked ? 0 : 5);
                ex.getResponseBody().write("hello".getBytes());
                if (chunked) ex.getResponseBody().write(" world".getBytes());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        try {
            String base = "http://localhost:" + s.getAddress().getPort();
            long deadline = System.nanoTime() + 5 * SEC;
            var r = PinnedHttp.open(URI.create(base + "/plain"), Map.of("Accept", "x"), deadline, a -> a.isLoopbackAddress());
            assertEquals(200, r.status());
            assertEquals("1", r.headers().firstValue("x-a").orElseThrow());
            assertEquals("hello", read(r));
            assertEquals("hello world", read(PinnedHttp.open(URI.create(base + "/chunked"), Map.of(), deadline,
                    a -> a.isLoopbackAddress())));
        } finally {
            s.stop(0);
        }
    }

    @Test
    void refusesWhenAnyAnswerIsNotAllowed() throws Exception {
        HttpServer s = server(ex -> { });
        try {
            var e = assertThrows(Failure.class, () -> PinnedHttp.open(
                    URI.create("http://127.0.0.1:" + s.getAddress().getPort() + "/"), Map.of(),
                    System.nanoTime() + 5 * SEC)); // default rule: loopback is not globally reachable
            assertEquals(Kind.ADDRESS_BLOCKED, e.kind());
        } finally {
            s.stop(0);
        }
    }

    @Test
    void deadlineCoversAStalledBody() throws Exception {
        HttpServer s = server(ex -> {
            try {
                ex.sendResponseHeaders(200, 100);
                ex.getResponseBody().write(new byte[25]);
                ex.getResponseBody().flush();
                Thread.sleep(6000);
            } catch (Exception ignored) {
                // test over
            }
        });
        try {
            long t0 = System.nanoTime();
            var r = PinnedHttp.open(URI.create("http://127.0.0.1:" + s.getAddress().getPort() + "/"), Map.of(),
                    System.nanoTime() + SEC, a -> true);
            assertThrows(java.io.IOException.class, () -> read(r));
            assertTrue((System.nanoTime() - t0) / 1e9 < 4);
        } finally {
            s.stop(0);
        }
    }

    /** Serves one canned response on a raw socket and returns the request line it saw. */
    static String rawServe(String response, java.util.function.Consumer<Integer> portSink, java.util.concurrent.atomic.AtomicReference<String> requestLine)
            throws Exception {
        java.net.ServerSocket ss = new java.net.ServerSocket(0, 1, InetAddress.getLoopbackAddress());
        portSink.accept(ss.getLocalPort());
        Thread t = new Thread(() -> {
            try (java.net.Socket c = ss.accept()) {
                var in = new java.io.BufferedReader(new java.io.InputStreamReader(c.getInputStream(), StandardCharsets.UTF_8));
                requestLine.set(in.readLine());
                for (String l; (l = in.readLine()) != null && !l.isEmpty(); ) { /* skip headers */ }
                c.getOutputStream().write(response.getBytes(StandardCharsets.UTF_8));
                c.getOutputStream().flush();
            } catch (Exception ignored) {
                // test over
            } finally {
                try { ss.close(); } catch (Exception ignored) { /* closed */ }
            }
        });
        t.setDaemon(true);
        t.start();
        return "ok";
    }

    @Test
    void skipsInterimResponsesAndEncodesNonAsciiPath() throws Exception {
        int[] port = new int[1];
        var line = new java.util.concurrent.atomic.AtomicReference<String>();
        rawServe("HTTP/1.1 103 Early Hints\r\nLink: </a>; rel=preload\r\n\r\nHTTP/1.1 100 Continue\r\n\r\n"
                + "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}", p -> port[0] = p, line);
        var r = PinnedHttp.open(URI.create("http://127.0.0.1:" + port[0] + "/ctx/\u00e9.jsonld?q=\u00e9"), Map.of(),
                System.nanoTime() + 5 * SEC, a -> true);
        assertEquals(200, r.status());
        assertEquals("{}", read(r));
        assertEquals("GET /ctx/%C3%A9.jsonld?q=%C3%A9 HTTP/1.1", line.get());
    }

    @Test
    void locationIsPercentEncodedAndBlankIsNotFollowed() throws Exception {
        URI base = URI.create("https://h.example/1.0/identifiers/did:x");
        assertEquals("https://h.example/a%20b", BoundedHttp.resolveLocation(base, "/a b").toString());
        assertEquals("https://h.example/a%7Cb%7Bc%7D%5E", BoundedHttp.resolveLocation(base, "/a|b{c}^").toString());
        assertEquals("https://h.example/ctx/%C3%A9.jsonld", BoundedHttp.resolveLocation(base, "/ctx/\u00e9.jsonld").toString());
        assertEquals("https://h.example/x%20y", BoundedHttp.resolveLocation(base, "/x%20y").toString()); // kept as is
        assertNull(BoundedHttp.resolveLocation(base, ""));
        assertNull(BoundedHttp.resolveLocation(base, "  "));
    }
}
