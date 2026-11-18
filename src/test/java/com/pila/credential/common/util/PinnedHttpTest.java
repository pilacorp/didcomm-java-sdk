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
}
