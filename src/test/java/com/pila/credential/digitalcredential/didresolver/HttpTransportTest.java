package com.pila.credential.digitalcredential.didresolver;

import static org.junit.jupiter.api.Assertions.*;

import com.pila.credential.common.util.BoundedHttp;
import com.pila.credential.common.util.BoundedHttp.Failure;
import com.pila.credential.common.util.BoundedHttp.Kind;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Map;

/** Ports of Go's TestHTTPBindingRequest / Status / Refusals against a local TLS server. */
class HttpTransportTest {
    static final String DID = "did:example:abc";
    HttpsServer server;
    HttpClient client;
    String base;

    @BeforeEach
    void start() throws Exception {
        Path ks = Files.createTempDirectory("ks").resolve("k.p12");
        Process p = new ProcessBuilder("keytool", "-genkeypair", "-alias", "t", "-keyalg", "EC", "-groupname", "secp256r1",
                "-dname", "CN=localhost", "-validity", "2", "-storetype", "PKCS12", "-keystore", ks.toString(),
                "-storepass", "changeit", "-ext", "san=dns:localhost,ip:127.0.0.1").redirectErrorStream(true).start();
        assertEquals(0, p.waitFor(), new String(p.getInputStream().readAllBytes()));
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (var in = Files.newInputStream(ks)) {
            store.load(in, "changeit".toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(store, "changeit".toCharArray());
        SSLContext serverCtx = SSLContext.getInstance("TLS");
        serverCtx.init(kmf.getKeyManagers(), null, null);
        server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(serverCtx));
        server.start();
        SSLContext clientCtx = SSLContext.getInstance("TLS");
        clientCtx.init(null, new TrustManager[] {new X509TrustManager() { // test certificate only
            public void checkClientTrusted(X509Certificate[] c, String a) {}
            public void checkServerTrusted(X509Certificate[] c, String a) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }}, null);
        client = HttpClient.newBuilder().sslContext(clientCtx).followRedirects(HttpClient.Redirect.NEVER).build();
        base = "https://127.0.0.1:" + server.getAddress().getPort() + "/1.0/identifiers";
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    void reply(String path, int status, String type, String body) {
        server.createContext(path, ex -> {
            byte[] b = body.getBytes(StandardCharsets.UTF_8);
            if (type != null) ex.getResponseHeaders().add("Content-Type", type);
            ex.sendResponseHeaders(status, b.length == 0 ? -1 : b.length);
            try (OutputStream o = ex.getResponseBody()) {
                o.write(b);
            }
        });
    }

    @Test
    void requestSendsDidAsOnePathSegmentAndReadsBody() throws Exception {
        String[] seen = new String[2];
        server.createContext("/1.0/identifiers/", ex -> {
            seen[0] = ex.getRequestURI().getRawPath();
            seen[1] = ex.getRequestHeaders().getFirst("Accept");
            byte[] b = "{\"id\":\"x\"}".getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", "application/did+json; charset=utf-8");
            ex.sendResponseHeaders(200, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        byte[] body = new HttpTransport(base, client).resolve("did:example:a%3Ab");
        assertEquals("{\"id\":\"x\"}", new String(body, StandardCharsets.UTF_8));
        assertEquals("/1.0/identifiers/did:example:a%253Ab", seen[0]); // "%" is escaped so the DID round-trips
        assertTrue(seen[1].startsWith("application/did-resolution"));
    }

    @Test
    void statusTable() throws Exception {
        reply("/1.0/identifiers/did:example:gone", 410, null, "");
        reply("/1.0/identifiers/did:example:bad", 400, null, "");
        reply("/1.0/identifiers/did:example:boom", 503, null, "");
        HttpTransport t = new HttpTransport(base, client);
        assertThrows(DidResolver.NoUsableKeyException.class, () -> t.resolve("did:example:gone"));
        assertThrows(DidResolver.IssuerNotSupportedException.class, () -> t.resolve("did:example:bad"));
        var e = assertThrows(BoundedHttp.StatusException.class, () -> t.resolve("did:example:boom"));
        assertEquals(503, e.code());
    }

    @Test
    void refusals() throws Exception {
        reply("/1.0/identifiers/did:example:html", 200, "text/html", "<html/>");
        server.createContext("/1.0/identifiers/did:example:away", ex -> {
            ex.getResponseHeaders().add("Location", "https://other.example/x");
            ex.sendResponseHeaders(302, -1);
            ex.close();
        });
        server.createContext("/1.0/identifiers/did:example:plain", ex -> {
            ex.getResponseHeaders().add("Location", "http://127.0.0.1/x");
            ex.sendResponseHeaders(302, -1);
            ex.close();
        });
        server.createContext("/1.0/identifiers/did:example:loop", ex -> {
            ex.getResponseHeaders().add("Location", ex.getRequestURI().getRawPath());
            ex.sendResponseHeaders(302, -1);
            ex.close();
        });
        reply("/1.0/identifiers/did:example:big", 200, "application/json", "x".repeat((1 << 20) + 1));
        HttpTransport t = new HttpTransport(base, client);
        assertEquals(Kind.CONTENT_TYPE_NOT_ACCEPTED, assertThrows(Failure.class, () -> t.resolve("did:example:html")).kind());
        assertEquals(Kind.REDIRECT_NOT_ALLOWED, assertThrows(Failure.class, () -> t.resolve("did:example:away")).kind());
        assertEquals(Kind.REDIRECT_TARGET_NOT_ALLOWED, assertThrows(Failure.class, () -> t.resolve("did:example:plain")).kind());
        assertEquals(Kind.TOO_MANY_REDIRECTS, assertThrows(Failure.class, () -> t.resolve("did:example:loop")).kind());
        assertEquals(Kind.BODY_TOO_LARGE, assertThrows(Failure.class, () -> t.resolve("did:example:big")).kind());
    }

    /** An empty Location must not turn a server failure into "DID not found". */
    @Test
    void blankLocationKeepsTheRedirectAsTheAnswer() throws Exception {
        server.createContext("/1.0/identifiers/did:example:zz", ex -> {
            ex.getResponseHeaders().add("Location", "");
            ex.sendResponseHeaders(302, -1);
            ex.close();
        });
        reply("/1.0/identifiers/", 404, null, ""); // what the old code reached by resolving "" to the directory
        var e = assertThrows(BoundedHttp.StatusException.class, () -> new HttpTransport(base, client).resolve("did:example:zz"));
        assertEquals(302, e.code());
    }

    @Test
    void locationWithIllegalCharactersIsFollowed() throws Exception {
        server.createContext("/1.0/identifiers/did:example:sp", ex -> {
            ex.getResponseHeaders().add("Location", "/1.0/identifiers/ok one");
            ex.sendResponseHeaders(302, -1);
            ex.close();
        });
        reply("/1.0/identifiers/ok one", 200, "application/json", "{\"id\":\"x\"}");
        assertEquals("{\"id\":\"x\"}", new String(new HttpTransport(base, client).resolve("did:example:sp")));
    }

    @Test
    void defaultClientRefusesALocalAddress() {
        Failure e = assertThrows(Failure.class, () -> new HttpTransport(base).resolve(DID));
        assertEquals(Kind.ADDRESS_BLOCKED, e.kind());
    }

    @Test
    void endpointMustBeHttps() {
        assertThrows(IllegalArgumentException.class, () -> new HttpTransport("http://resolver.example/x"));
        assertThrows(IllegalArgumentException.class, () -> new HttpTransport("https://u:p@resolver.example/x"));
        assertThrows(IllegalArgumentException.class, () -> new HttpTransport("https://resolver.example/x?a=b"));
    }

    /** S9'/D1: the deadline covers the body, not just the headers. */
    @Test
    void drippedBodyHitsTheDeadline() throws Exception {
        HttpServer plain = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        plain.createContext("/", ex -> {
            ex.sendResponseHeaders(200, 100);
            ex.getResponseBody().write(new byte[25]);
            ex.getResponseBody().flush();
            try {
                Thread.sleep(8000);
            } catch (InterruptedException ignored) {
                // stopped by the test
            }
            ex.close();
        });
        plain.start();
        try {
            long t0 = System.nanoTime();
            HttpClient c = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
            Failure e = assertThrows(Failure.class, () -> BoundedHttp.get(c,
                    URI.create("http://127.0.0.1:" + plain.getAddress().getPort() + "/"), Map.of(),
                    Duration.ofSeconds(1), 3, 1 << 20, null));
            assertEquals(Kind.TIMEOUT, e.kind());
            assertTrue((System.nanoTime() - t0) / 1e9 < 4);
        } finally {
            plain.stop(0);
        }
    }
}
