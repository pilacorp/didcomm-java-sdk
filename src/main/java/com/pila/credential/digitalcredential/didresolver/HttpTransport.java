package com.pila.credential.digitalcredential.didresolver;

import com.pila.credential.common.processor.RemoteContextLoader;

import java.io.InputStream;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Locale;

/**
 * The HTTP(S) binding of DID Resolution §9.1: https only, redirects only within the origin of the endpoint
 * (at most 3), 1 MiB body, 5 s for the whole exchange, content type one of the JSON forms, and addresses that
 * are not globally reachable refused (a resolver on a private network needs its own {@link DidResolver.Transport}).
 */
public final class HttpTransport implements DidResolver.Transport {
    private static final List<String> MEDIA_TYPES = List.of("application/did-resolution", "application/did",
            "application/did+json", "application/did+ld+json", "application/ld+json", "application/json");
    private static final int MAX_REDIRECTS = 3;
    private static final int MAX_BYTES = 1 << 20;
    private static final Duration TIMEOUT = Duration.ofSeconds(5);

    private final String endpoint;
    private final URI origin;
    private final HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER)
            .proxy(HttpClient.Builder.NO_PROXY).connectTimeout(TIMEOUT).build();

    /** @param endpoint e.g. https://resolver.example/1.0/identifiers; the DID is appended to it. */
    public HttpTransport(String endpoint) {
        URI u;
        try {
            u = URI.create(endpoint);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("didresolver: endpoint must be https, without userinfo, query or fragment");
        }
        if (!httpsWithHost(u) || endpoint.contains("?") || endpoint.contains("#")) {
            throw new IllegalArgumentException("didresolver: endpoint must be https, without userinfo, query or fragment");
        }
        this.endpoint = endpoint.replaceAll("/+$", "");
        this.origin = u;
    }

    private static boolean httpsWithHost(URI u) {
        return "https".equalsIgnoreCase(u.getScheme()) && u.getHost() != null && u.getRawUserInfo() == null;
    }

    private static boolean sameOrigin(URI a, URI b) {
        return a.getScheme().equalsIgnoreCase(b.getScheme()) && a.getHost().equalsIgnoreCase(b.getHost())
                && port(a) == port(b);
    }

    private static int port(URI u) {
        return u.getPort() >= 0 ? u.getPort() : 443;
    }

    @Override
    public byte[] resolve(String did) throws Exception {
        // PathEscape keeps ":" and turns "%" into "%25", so the resolver decodes back the exact DID.
        URI uri = URI.create(endpoint + "/" + did.replace("%", "%25"));
        long deadline = System.nanoTime() + TIMEOUT.toNanos();
        for (int redirects = 0; ; redirects++) {
            for (InetAddress a : InetAddress.getAllByName(uri.getHost())) {
                if (!RemoteContextLoader.isPublic(a)) {
                    throw new Exception("didresolver: resolver request failed: address is not globally reachable");
                }
            }
            long left = deadline - System.nanoTime();
            if (left <= 0) {
                throw new Exception("didresolver: resolver request failed: timed out");
            }
            HttpResponse<InputStream> res = client.send(HttpRequest.newBuilder(uri).timeout(Duration.ofNanos(left))
                    .header("Accept", String.join(", ", MEDIA_TYPES)).GET().build(),
                    HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream in = res.body()) {
                int status = res.statusCode();
                if (status >= 300 && status < 400 && res.headers().firstValue("location").isPresent()) {
                    if (redirects >= MAX_REDIRECTS) {
                        throw new Exception("didresolver: resolver request failed: too many redirects");
                    }
                    URI next = uri.resolve(res.headers().firstValue("location").get());
                    if (!httpsWithHost(next)) {
                        throw new Exception("didresolver: resolver request failed: redirect target not allowed");
                    }
                    if (!sameOrigin(origin, next)) {
                        throw new Exception("didresolver: resolver request failed: redirect leaves the endpoint's origin");
                    }
                    uri = next;
                    continue;
                }
                if (status != 200) {
                    Exception a = DidResolver.answer(status, "status " + status);
                    throw a != null ? a : new Exception("didresolver: resolver request failed: status " + status);
                }
                String ct = res.headers().firstValue("content-type").orElse("");
                String type = ct.split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
                if (!MEDIA_TYPES.contains(type)) {
                    throw new Exception("didresolver: resolver request failed: content type not accepted");
                }
                byte[] body = in.readNBytes(MAX_BYTES + 1);
                if (body.length > MAX_BYTES) {
                    throw new Exception("didresolver: resolver request failed: body too large");
                }
                return body;
            }
        }
    }
}
