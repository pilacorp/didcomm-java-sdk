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
import java.util.concurrent.Executors;
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

    private static final Set<Integer> REDIRECTS = Set.of(301, 302, 303, 307, 308);
    private static final ScheduledExecutorService WATCHDOG = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "bounded-http-watchdog");
        t.setDaemon(true);
        return t;
    });

    private BoundedHttp() {
    }

    /**
     * @param guard called with every URI before it is requested; throws to refuse it (may be null)
     * @return the final response; its body is read only for a 2xx status, so an error page costs nothing
     */
    public static Response get(HttpClient client, URI uri, Map<String, String> headers, Duration total,
            int maxRedirects, int maxBytes, UriGuard guard) throws IOException, InterruptedException {
        long deadline = System.nanoTime() + total.toNanos();
        for (int hops = 0; ; hops++) {
            if (guard != null) {
                guard.check(uri);
            }
            long left = deadline - System.nanoTime();
            if (left <= 0) {
                throw new Failure(Kind.TIMEOUT, "request timed out");
            }
            HttpRequest.Builder b = HttpRequest.newBuilder(uri).timeout(Duration.ofNanos(left)).GET();
            headers.forEach(b::header);
            HttpResponse<InputStream> res;
            try {
                res = client.send(b.build(), HttpResponse.BodyHandlers.ofInputStream());
            } catch (java.net.http.HttpTimeoutException e) {
                throw new Failure(Kind.TIMEOUT, "request timed out");
            }
            try (InputStream in = res.body()) {
                int status = res.statusCode();
                var location = res.headers().firstValue("location");
                if (REDIRECTS.contains(status) && location.isPresent()) {
                    if (hops >= maxRedirects) {
                        throw new Failure(Kind.TOO_MANY_REDIRECTS, "stopped after " + maxRedirects + " redirects");
                    }
                    uri = uri.resolve(location.get());
                    continue;
                }
                byte[] body = status / 100 == 2 ? readBounded(in, deadline, maxBytes) : new byte[0];
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
