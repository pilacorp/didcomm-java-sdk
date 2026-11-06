package com.pila.credential.common.processor;

import com.apicatalog.jsonld.document.JsonDocument;
import com.pila.credential.common.processor.JsonLdLimitException.Kind;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Bounded fetch and cache of remote @context documents (go-credential-sdk document_loader.go).
 * A document under verification names its own context URLs and canonicalization runs before the
 * signature check, so every limit here faces an unauthenticated caller.
 */
public final class RemoteContextLoader {

    /** Far above any published context (schema.org's is ~150 KB). */
    static final int MAX_CONTEXT_BYTES = 1 << 20;
    /** HTTP requests of one fetch: redirects and Link rel=alternate hops. */
    static final int MAX_CONTEXT_REQUESTS = 16;
    /** The cache holds bytes, so this bounds it to 64 MiB. */
    static final int MAX_CACHED_CONTEXTS = 64;

    /** Bounds one fetch: all its requests, each body included. Tests shorten it. */
    static volatile Duration fetchTimeout = Duration.ofSeconds(10);

    private static final HttpClient DEFAULT_CLIENT = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER) // redirects are followed below, counted and address-checked per hop
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    private static final ScheduledExecutorService WATCHDOG = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "jsonld-context-watchdog");
        t.setDaemon(true);
        return t;
    });

    private static volatile RemoteContextLoader current = new RemoteContextLoader(DEFAULT_CLIENT);

    record Fetched(byte[] raw, URI documentUrl) {
    }

    private final HttpClient client;
    final LinkedHashMap<String, Fetched> docs = new LinkedHashMap<>();

    RemoteContextLoader(HttpClient client) {
        this.client = client;
    }

    static RemoteContextLoader current() {
        return current;
    }

    /**
     * Replaces the process-wide client that fetches remote contexts and empties the cache. The
     * refusal of non-public addresses lives in the default client's path, so a client set here drops
     * it for every fetch in the process; whatever it connects through must do the filtering. The
     * time, size, scheme and request limits still apply. null restores the default.
     */
    public static void setHttpClient(HttpClient client) {
        current = new RemoteContextLoader(client == null ? DEFAULT_CLIENT : client);
    }

    /** Fetch (or serve from cache) a context. Every failure is Kind.LOAD with the cause on the chain. */
    Fetched load(String url) throws JsonLdLimitException {
        synchronized (docs) {
            Fetched hit = docs.get(url);
            if (hit != null) return hit;
        }
        Fetched f;
        try {
            f = fetch(url);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw loadError(e);
        } catch (Exception e) {
            throw loadError(e);
        }
        synchronized (docs) {
            if (docs.size() >= MAX_CACHED_CONTEXTS) {
                // Evict rather than stop caching, so filling the cache once leaves later contexts cacheable.
                docs.remove(docs.keySet().iterator().next());
            }
            docs.put(url, f);
        }
        return f;
    }

    /** The cause stays off the text, which would tell the caller whether an address or port answered. */
    private static JsonLdLimitException loadError(Throwable cause) {
        return new JsonLdLimitException(Kind.LOAD, "remote context could not be loaded", cause);
    }

    private Fetched fetch(String rawUrl) throws Exception {
        URI uri = httpUri(rawUrl);
        long deadline = System.nanoTime() + fetchTimeout.toNanos();
        boolean checkAddress = client == DEFAULT_CLIENT;
        for (int requests = 1; ; requests++) {
            if (requests > MAX_CONTEXT_REQUESTS) {
                throw new JsonLdLimitException(Kind.REQUESTS, "context fetch made too many requests");
            }
            if (checkAddress) refuseNonPublic(uri);
            long left = deadline - System.nanoTime();
            if (left <= 0) throw new TimeoutException("context fetch timed out");
            HttpRequest req = HttpRequest.newBuilder(uri)
                    .timeout(Duration.ofNanos(left))
                    .header("Accept", "application/ld+json, application/json;q=0.9")
                    .GET().build();
            HttpResponse<InputStream> res = client.send(req, HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream in = res.body()) {
                // json-gold-style loaders load an alternate themselves, so every one is scheme-checked.
                List<URI> alternates = new ArrayList<>();
                for (String target : alternateTargets(res.headers())) alternates.add(httpTarget(uri, target));

                int status = res.statusCode();
                if (status >= 300 && status < 400) {
                    String loc = res.headers().firstValue("location").orElseThrow(() -> new IOException("redirect without Location"));
                    uri = httpTarget(uri, loc);
                    continue;
                }
                if (status != 200) throw new IOException("status " + status);

                String type = res.headers().firstValue("content-type").orElse("").toLowerCase(Locale.ROOT);
                int semi = type.indexOf(';');
                if (semi >= 0) type = type.substring(0, semi);
                type = type.trim();
                boolean ldJson = type.equals("application/ld+json");
                if (!ldJson && !alternates.isEmpty()) {
                    uri = alternates.get(0);
                    continue;
                }
                // Any other type is parsed as JSON too (json-gold does the same); a non-JSON body fails the parse below.
                byte[] raw = readBounded(in, deadline);
                JsonDocument.of(new ByteArrayInputStream(raw)); // must parse
                return new Fetched(raw, uri);
            }
        }
    }

    private static byte[] readBounded(InputStream in, long deadline) throws IOException, TimeoutException {
        ScheduledFuture<?> stop = WATCHDOG.schedule(() -> {
            try {
                in.close();
            } catch (IOException ignored) {
                // closing is how a stalled read is interrupted
            }
        }, Math.max(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
        try {
            byte[] body = in.readNBytes(MAX_CONTEXT_BYTES + 1);
            if (body.length > MAX_CONTEXT_BYTES) throw new IOException("context body exceeds " + MAX_CONTEXT_BYTES + " bytes");
            return body;
        } catch (IOException e) {
            if (System.nanoTime() - deadline >= 0) throw new TimeoutException("context fetch timed out");
            throw e;
        } finally {
            stop.cancel(false);
        }
    }

    private static URI httpUri(String raw) throws JsonLdLimitException {
        try {
            URI u = new URI(raw);
            String s = u.getScheme();
            if (u.getHost() != null && ("http".equalsIgnoreCase(s) || "https".equalsIgnoreCase(s))) return u;
        } catch (URISyntaxException ignored) {
            // falls through to the refusal
        }
        throw new JsonLdLimitException(Kind.SCHEME, "context URL is not http or https");
    }

    private static URI httpTarget(URI base, String target) throws JsonLdLimitException {
        try {
            return httpUri(base.resolve(new URI(target)).toString());
        } catch (URISyntaxException e) {
            throw new JsonLdLimitException(Kind.SCHEME, "context URL is not http or https");
        }
    }

    private static final Pattern LINK = Pattern.compile("<([^>]*)>([^,]*)");
    private static final Pattern REL_ALTERNATE = Pattern.compile("(?i)rel\\s*=\\s*\"?alternate\"?(?=[\\s;\"]|$)");
    private static final Pattern TYPE_LD = Pattern.compile("(?i)type\\s*=\\s*\"?application/ld\\+json\"?");

    private static List<String> alternateTargets(HttpHeaders headers) {
        List<String> out = new ArrayList<>();
        for (String value : headers.allValues("link")) {
            Matcher m = LINK.matcher(value);
            while (m.find()) {
                if (REL_ALTERNATE.matcher(m.group(2)).find() && TYPE_LD.matcher(m.group(2)).find()) out.add(m.group(1));
            }
        }
        return out;
    }

    // --- address check (table of go digitalcredential/internal/safehttp) ---

    private record Prefix(byte[] addr, int bits) {
        boolean contains(byte[] a) {
            if (a.length != addr.length) return false;
            for (int i = 0; i < bits; i++) {
                int mask = 0x80 >> (i % 8);
                if ((a[i / 8] & mask) != (addr[i / 8] & mask)) return false;
            }
            return true;
        }
    }

    /** IANA special-purpose entries that are not globally reachable, plus multicast and site-local. */
    private static final List<Prefix> NON_PUBLIC = List.of(
            "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
            "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
            "192.88.99.2/32", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
            "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
            "64:ff9b:1::/48", "100::/64", "100:0:0:1::/64", "2001::/23", "2001:db8::/32",
            "3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8"
    ).stream().map(p -> {
        try {
            int slash = p.indexOf('/');
            return new Prefix(InetAddress.getByName(p.substring(0, slash)).getAddress(), Integer.parseInt(p.substring(slash + 1)));
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }).toList();

    /** Whether ip may be connected to. An IPv6 address that carries an IPv4 address is judged by it. */
    static boolean isPublic(InetAddress ip) {
        byte[] b = ip.getAddress();
        if (b.length == 16) {
            if (zeros(b, 0, 10) && b[10] == (byte) 0xff && b[11] == (byte) 0xff) b = java.util.Arrays.copyOfRange(b, 12, 16); // ::ffff:a.b.c.d
            else if (zeros(b, 0, 12)) b = java.util.Arrays.copyOfRange(b, 12, 16); // ::/96 IPv4-compatible
            else if (b[0] == 0 && b[1] == 0x64 && b[2] == (byte) 0xff && b[3] == (byte) 0x9b && zeros(b, 4, 12)) b = java.util.Arrays.copyOfRange(b, 12, 16); // NAT64
            else if (b[0] == 0x20 && b[1] == 0x02) b = java.util.Arrays.copyOfRange(b, 2, 6); // 6to4
        }
        for (Prefix p : NON_PUBLIC) if (p.contains(b)) return false;
        return true;
    }

    private static boolean zeros(byte[] b, int from, int to) {
        for (int i = from; i < to; i++) if (b[i] != 0) return false;
        return true;
    }

    /**
     * Resolves the host and refuses if any address is non-public. ponytail: the JDK client cannot be
     * pinned to the checked address, so a DNS answer that changes between this check and the connect
     * (rebinding) is not caught; Go checks the dialed address. Pin by supplying a client whose
     * socket factory connects to the address returned here.
     */
    static void refuseNonPublic(URI uri) throws Exception {
        String host = uri.getHost();
        if (host == null || host.isEmpty()) throw new JsonLdLimitException(Kind.ADDRESS, "context address is not public");
        if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
        for (InetAddress a : InetAddress.getAllByName(host)) {
            if (!isPublic(a)) throw new JsonLdLimitException(Kind.ADDRESS, "context address is not public");
        }
    }
}
