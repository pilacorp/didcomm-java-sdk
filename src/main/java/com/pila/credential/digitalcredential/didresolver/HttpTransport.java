package com.pila.credential.digitalcredential.didresolver;

import com.pila.credential.common.util.PinnedHttp;
import com.pila.credential.common.util.BoundedHttp;
import com.pila.credential.common.util.BoundedHttp.Failure;
import com.pila.credential.common.util.BoundedHttp.Kind;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The HTTP(S) binding of DID Resolution §9.1: https only, redirects only within the origin of the endpoint
 * (at most 3), 1 MiB body, 5 s for the whole exchange (body included), content type one of the JSON forms.
 * The default connection refuses addresses that are not globally reachable and connects to the address it checked; a resolver on a private network
 * needs {@link #HttpTransport(String, HttpClient)} with a client of the deployment, which is then trusted as is
 * (it must not follow redirects itself: use {@code Redirect.NEVER}).
 *
 * <p>Refusals are {@link Failure}s told apart by {@link Failure#kind()}; an unexpected status is a
 * {@link BoundedHttp.StatusException} carrying the code (Go {@code StatusError}).
 */
public final class HttpTransport implements DidResolver.Transport {
    private static final List<String> MEDIA_TYPES = List.of("application/did-resolution", "application/did",
            "application/did+json", "application/did+ld+json", "application/ld+json", "application/json");
    private static final int MAX_REDIRECTS = 3;
    private static final int MAX_BYTES = 1 << 20;
    private static final Duration TIMEOUT = Duration.ofSeconds(5);

    private final String endpoint;
    private final URI origin;
    private final BoundedHttp.Opener opener;

    /** @param endpoint e.g. https://resolver.example/1.0/identifiers; the DID is appended to it. */
    public HttpTransport(String endpoint) {
        this(endpoint, null);
    }

    /** @param client sends the requests; null uses a client that refuses non-public addresses. */
    public HttpTransport(String endpoint, HttpClient client) {
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
        // Default: connect to the address checked for this very request (no rebinding window, no proxy).
        this.opener = client != null ? BoundedHttp.jdk(client) : PinnedHttp::open;
    }

    private static boolean httpsWithHost(URI u) {
        return "https".equalsIgnoreCase(u.getScheme()) && u.getHost() != null && u.getRawUserInfo() == null;
    }

    private static int port(URI u) {
        return u.getPort() >= 0 ? u.getPort() : 443;
    }

    private void guard(URI uri) throws IOException {
        if (!httpsWithHost(uri)) {
            throw new Failure(Kind.REDIRECT_TARGET_NOT_ALLOWED, "redirect target is not https with a host");
        }
        if (!uri.getHost().equalsIgnoreCase(origin.getHost()) || port(uri) != port(origin)) {
            throw new Failure(Kind.REDIRECT_NOT_ALLOWED, "redirect leaves the endpoint's origin");
        }
    }

    @Override
    public byte[] resolve(String did) throws Exception {
        // PathEscape keeps ":" and turns "%" into "%25", so the resolver decodes back the exact DID.
        URI uri = URI.create(endpoint + "/" + did.replace("%", "%25"));
        BoundedHttp.Response res = BoundedHttp.get(opener, uri, Map.of("Accept", String.join(", ", MEDIA_TYPES)),
                TIMEOUT, MAX_REDIRECTS, MAX_BYTES, this::guard);
        int status = res.status();
        if (status / 100 != 2) {
            Exception a = DidResolver.answer(status, "status " + status);
            throw a != null ? a : new BoundedHttp.StatusException(status);
        }
        String ct = res.headers().firstValue("content-type").orElse("");
        String type = ct.split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
        if (!MEDIA_TYPES.contains(type)) {
            throw new Failure(Kind.CONTENT_TYPE_NOT_ACCEPTED, "content type not accepted");
        }
        return res.body();
    }
}
