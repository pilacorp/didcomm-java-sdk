package com.pila.credential.common.util;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * A GET that is bounded as a whole, like Go's {@code http.Client{Timeout}}: one deadline covers connecting,
 * every redirect hop and the body (the JDK's {@code HttpRequest.timeout} stops at the response headers, so a
 * server that sends headers and then drips the body would block forever). The client must not follow
 * redirects itself ({@code Redirect.NEVER}): they are followed here, counted, and each target is vetted.
 */
public final class BoundedHttp {
    public enum Kind { TIMEOUT, TOO_MANY_REDIRECTS, BODY_TOO_LARGE, REDIRECT_NOT_ALLOWED, REDIRECT_TARGET_NOT_ALLOWED,
        CONTENT_TYPE_NOT_ACCEPTED, ADDRESS_BLOCKED }

    /** A refusal of the exchange, told apart by {@link #kind()}. */
    public static class Failure extends IOException {
        private final Kind kind;

        public Failure(Kind kind, String message) {
            super(message);
            this.kind = kind;
        }

        public Kind kind() {
            return kind;
        }
    }

    /** The server answered with a status the caller treats as an error. */
    public static class StatusException extends IOException {
        private final int code;

        public StatusException(int code) {
            super("unexpected status " + code);
            this.code = code;
        }

        public int code() {
            return code;
        }
    }

    /** Vets a URI before a request is sent to it (the first one and every redirect target). */
    @FunctionalInterface
    public interface UriGuard {
        void check(URI uri) throws IOException;
    }

    public record Response(int status, HttpHeaders headers, byte[] body) {
    }

    /** An open response: status, headers and a body stream; closing it releases the connection. */
    public record Reply(int status, HttpHeaders headers, InputStream body) implements java.io.Closeable {
        @Override
        public void close() throws IOException {
            body.close();
        }
    }

    /** Sends one GET and returns when the headers are in; the deadline is a System.nanoTime() value. */
    @FunctionalInterface
    public interface Opener {
        Reply open(URI uri, Map<String, String> headers, long deadlineNanos) throws IOException, InterruptedException;
    }

    /** The JDK client as an Opener (it resolves the host itself on connect). */
    public static Opener jdk(HttpClient client) {
        return (uri, headers, deadline) -> {
            long left = deadline - System.nanoTime();
            if (left <= 0) {
                throw new Failure(Kind.TIMEOUT, "request timed out");
            }
            HttpRequest.Builder b = HttpRequest.newBuilder(uri).timeout(Duration.ofNanos(left)).GET();
            headers.forEach(b::header);
            try {
                HttpResponse<InputStream> res = client.send(b.build(), HttpResponse.BodyHandlers.ofInputStream());
                return new Reply(res.statusCode(), res.headers(), res.body());
            } catch (java.net.http.HttpTimeoutException e) {
                throw new Failure(Kind.TIMEOUT, "request timed out");
            }
        };
    }

    private static final Set<Integer> REDIRECTS = Set.of(301, 302, 303, 307, 308);
    private static final ScheduledExecutorService WATCHDOG = watchdog("bounded-http-watchdog");

    /** A daemon timer whose cancelled tasks leave the queue at once (not at their deadline). */
    public static ScheduledExecutorService watchdog(String name) {
        java.util.concurrent.ScheduledThreadPoolExecutor ex = new java.util.concurrent.ScheduledThreadPoolExecutor(1, r -> {
            Thread t = new Thread(r, name);
            t.setDaemon(true);
            return t;
        });
        ex.setRemoveOnCancelPolicy(true);
        return ex;
    }

    /**
     * Resolves a {@code Location} like Go's {@code url.Parse}+{@code ResolveReference}: characters illegal in a
     * URI (space, {@code | { } ^ ` < > " \} and non-ASCII, as UTF-8) are percent-encoded, existing {@code %XX}
     * stay. Returns null for a blank value (the caller then keeps the 3xx as the answer).
     */
    public static URI resolveLocation(URI base, String location) throws Failure {
        if (location == null || location.isBlank()) {
            return null;
        }
        StringBuilder b = new StringBuilder();
        for (byte x : location.strip().getBytes(java.nio.charset.StandardCharsets.UTF_8)) {
            int c = x & 0xff;
            if (c <= 0x20 || c >= 0x7f || "\"<>\\^`{|}".indexOf(c) >= 0) {
                b.append('%').append(String.format("%02X", c));
            } else {
                b.append((char) c);
            }
        }
        try {
            return base.resolve(new URI(b.toString()));
        } catch (java.net.URISyntaxException e) {
            throw new Failure(Kind.REDIRECT_TARGET_NOT_ALLOWED, "redirect target is not a valid URL");
        }
    }

    private BoundedHttp() {
    }

    /**
     * @param guard called with every URI before it is requested; throws to refuse it (may be null)
     * @return the final response; its body is read only for a 2xx status, so an error page costs nothing
     */
    public static Response get(HttpClient client, URI uri, Map<String, String> headers, Duration total,
            int maxRedirects, int maxBytes, UriGuard guard) throws IOException, InterruptedException {
        return get(jdk(client), uri, headers, total, maxRedirects, maxBytes, guard);
    }

    public static Response get(Opener opener, URI uri, Map<String, String> headers, Duration total,
            int maxRedirects, int maxBytes, UriGuard guard) throws IOException, InterruptedException {
        long deadline = System.nanoTime() + total.toNanos();
        for (int hops = 0; ; hops++) {
            if (guard != null) {
                guard.check(uri);
            }
            try (Reply res = opener.open(uri, headers, deadline)) {
                int status = res.status();
                URI next = REDIRECTS.contains(status)
                        ? resolveLocation(uri, res.headers().firstValue("location").orElse(null)) : null;
                if (next != null) {
                    if (hops >= maxRedirects) {
                        throw new Failure(Kind.TOO_MANY_REDIRECTS, "stopped after " + maxRedirects + " redirects");
                    }
                    uri = next;
                    continue;
                }
                byte[] body = status / 100 == 2 ? readBounded(res.body(), deadline, maxBytes) : new byte[0];
                return new Response(status, res.headers(), body);
            }
        }
    }

    /** Reads at most {@code maxBytes} before {@code deadline} (a System.nanoTime() value); closes the stream to stop a stall. */
    public static byte[] readBounded(InputStream in, long deadline, int maxBytes) throws IOException {
        ScheduledFuture<?> stop = WATCHDOG.schedule(() -> {
            try {
                in.close();
            } catch (IOException ignored) {
                // closing is how a stalled read is interrupted
            }
        }, Math.max(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
        try {
            byte[] body = in.readNBytes(maxBytes + 1);
            if (body.length > maxBytes) {
                throw new Failure(Kind.BODY_TOO_LARGE, "body exceeds " + maxBytes + " bytes");
            }
            return body;
        } catch (Failure e) {
            throw e;
        } catch (IOException e) {
            if (System.nanoTime() - deadline >= 0) {
                throw new Failure(Kind.TIMEOUT, "request timed out");
            }
            throw e;
        } finally {
            stop.cancel(false);
        }
    }
}
