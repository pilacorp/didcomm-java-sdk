package com.pila.credential.common.util;

import com.pila.credential.common.processor.RemoteContextLoader;
import com.pila.credential.common.util.BoundedHttp.Failure;
import com.pila.credential.common.util.BoundedHttp.Kind;
import com.pila.credential.common.util.BoundedHttp.Reply;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpHeaders;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * One HTTP/1.1 GET that connects to an address it has checked itself, closing the DNS-rebinding window of
 * {@code java.net.http.HttpClient} (which resolves again on connect). Go checks the dialed address in
 * {@code Dialer.Control}; this does the same: it resolves the host once, refuses the request if any answer is
 * not globally reachable, and connects to that very {@link InetAddress}. For https the TLS socket is layered
 * over it with the real host name, so SNI and certificate host-name checks are unchanged. No proxy is used.
 * The deadline covers connect, handshake, headers and the body; the caller closes the reply.
 */
public final class PinnedHttp {
    private static final int MAX_HEAD_BYTES = 64 * 1024;
    private static final ScheduledExecutorService WATCHDOG = BoundedHttp.watchdog("pinned-http-watchdog");

    private PinnedHttp() {
    }

    public static Reply open(URI uri, Map<String, String> headers, long deadline) throws IOException {
        return open(uri, headers, deadline, RemoteContextLoader::isPublic);
    }

    /** @param allowed decides which resolved addresses may be dialed (tests allow loopback). */
    static Reply open(URI uri, Map<String, String> headers, long deadline,
            java.util.function.Predicate<InetAddress> allowed) throws IOException {
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        boolean tls = scheme.equals("https");
        if ((!tls && !scheme.equals("http")) || uri.getHost() == null) {
            throw new IOException("not an http(s) URL");
        }
        String host = uri.getHost();
        if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
        int port = uri.getPort() >= 0 ? uri.getPort() : tls ? 443 : 80;
        InetAddress[] addrs = resolve(host, deadline);
        for (InetAddress a : addrs) {
            if (!allowed.test(a)) throw new Failure(Kind.ADDRESS_BLOCKED, "address is not globally reachable");
        }
        Socket sock = connect(addrs, port, deadline);
        ScheduledFuture<?> stop = WATCHDOG.schedule(() -> closeQuietly(sock), Math.max(0, deadline - System.nanoTime()),
                TimeUnit.NANOSECONDS);
        try {
            Socket io = sock;
            if (tls) {
                SSLSocket ss = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket(sock, host, port, true);
                SSLParameters p = ss.getSSLParameters();
                p.setEndpointIdentificationAlgorithm("HTTPS");
                ss.setSSLParameters(p);
                ss.startHandshake();
                io = ss;
            }
            URI ascii = URI.create(uri.toASCIIString()); // non-ASCII path/query goes out as %XX (UTF-8), like Go
            String path = (ascii.getRawPath() == null || ascii.getRawPath().isEmpty() ? "/" : ascii.getRawPath())
                    + (ascii.getRawQuery() == null ? "" : "?" + ascii.getRawQuery());
            StringBuilder req = new StringBuilder("GET ").append(path).append(" HTTP/1.1\r\nHost: ").append(uri.getHost())
                    .append(uri.getPort() >= 0 ? ":" + uri.getPort() : "").append("\r\nConnection: close\r\n");
            headers.forEach((k, v) -> req.append(k).append(": ").append(v.replaceAll("[\\r\\n]", " ")).append("\r\n"));
            io.getOutputStream().write(req.append("\r\n").toString().getBytes(StandardCharsets.US_ASCII));
            io.getOutputStream().flush();
            InputStream in = new java.io.BufferedInputStream(io.getInputStream());
            int[] budget = {0};
            int status;
            Map<String, List<String>> h;
            do { // an interim 1xx (100 Continue, 103 Early Hints) is skipped; the final head follows
                String statusLine = readLine(in, budget);
                String[] sl = statusLine.split(" ", 3);
                if (sl.length < 2 || !sl[0].startsWith("HTTP/1.") || !sl[1].matches("\\d{3}")) {
                    throw new IOException("malformed response");
                }
                status = Integer.parseInt(sl[1]);
                h = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
                for (String line; !(line = readLine(in, budget)).isEmpty(); ) {
                    int c = line.indexOf(':');
                    if (c <= 0) throw new IOException("malformed response header");
                    h.computeIfAbsent(line.substring(0, c).trim().toLowerCase(Locale.ROOT), k -> new ArrayList<>())
                            .add(line.substring(c + 1).trim());
                }
            } while (status / 100 == 1 && status != 101);
            HttpHeaders hh = HttpHeaders.of(h, (k, v) -> true);
            InputStream body = body(in, status, hh);
            return new Reply(status, hh, new FilterInputStream(body) {
                @Override
                public void close() throws IOException {
                    stop.cancel(false);
                    closeQuietly(sock);
                }
            });
        } catch (IOException | RuntimeException e) {
            stop.cancel(false);
            closeQuietly(sock);
            if (System.nanoTime() - deadline >= 0) throw new Failure(Kind.TIMEOUT, "request timed out");
            throw e;
        }
    }

    /** DNS under the same deadline (Go's DialContext bounds it too). */
    private static InetAddress[] resolve(String host, long deadline) throws IOException {
        java.util.concurrent.CompletableFuture<InetAddress[]> f = java.util.concurrent.CompletableFuture.supplyAsync(() -> {
            try {
                return InetAddress.getAllByName(host);
            } catch (IOException e) {
                throw new java.util.concurrent.CompletionException(e);
            }
        });
        try {
            return f.get(Math.max(1, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
        } catch (java.util.concurrent.TimeoutException e) {
            f.cancel(true);
            throw new Failure(Kind.TIMEOUT, "request timed out");
        } catch (java.util.concurrent.ExecutionException e) {
            throw e.getCause() instanceof IOException io ? io : new IOException(e.getCause());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted", e);
        }
    }

    private static Socket connect(InetAddress[] addrs, int port, long deadline) throws IOException {
        IOException last = null;
        for (InetAddress a : addrs) {
            long leftMs = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime());
            if (leftMs <= 0) throw new Failure(Kind.TIMEOUT, "request timed out");
            Socket s = new Socket();
            try {
                s.connect(new InetSocketAddress(a, port), (int) Math.min(leftMs, Integer.MAX_VALUE));
                return s;
            } catch (java.net.SocketTimeoutException e) {
                closeQuietly(s);
                throw new Failure(Kind.TIMEOUT, "request timed out");
            } catch (IOException e) {
                closeQuietly(s);
                last = e;
            }
        }
        throw last != null ? last : new IOException("no address");
    }

    private static InputStream body(InputStream in, int status, HttpHeaders h) {
        if (status / 100 == 1 || status == 204 || status == 304) return InputStream.nullInputStream();
        if (h.firstValue("transfer-encoding").map(v -> v.toLowerCase(Locale.ROOT).contains("chunked")).orElse(false)) {
            return new Chunked(in);
        }
        var len = h.firstValue("content-length");
        if (len.isPresent() && len.get().matches("\\d{1,15}")) return new Limited(in, Long.parseLong(len.get()));
        return in; // Connection: close, read to EOF
    }

    private static String readLine(InputStream in, int[] budget) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        for (int c; (c = in.read()) != '\n'; ) {
            if (c < 0) throw new EOFException("connection closed in the response head");
            if (++budget[0] > MAX_HEAD_BYTES) throw new IOException("response head too large");
            b.write(c);
        }
        String s = b.toString(StandardCharsets.UTF_8); // a raw UTF-8 Location must survive
        return s.endsWith("\r") ? s.substring(0, s.length() - 1) : s;
    }

    private static void closeQuietly(Socket s) {
        try {
            s.close();
        } catch (IOException ignored) {
            // closing is how a stalled read is interrupted
        }
    }

    private static final class Limited extends InputStream {
        private final InputStream in;
        private long left;

        Limited(InputStream in, long n) {
            this.in = in;
            this.left = n;
        }

        @Override
        public int read() throws IOException {
            if (left <= 0) return -1;
            int c = in.read();
            if (c < 0) throw new EOFException("body shorter than Content-Length");
            left--;
            return c;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (left <= 0) return -1;
            int n = in.read(b, off, (int) Math.min(len, left));
            if (n < 0) throw new EOFException("body shorter than Content-Length");
            left -= n;
            return n;
        }
    }

    private static final class Chunked extends InputStream {
        private final InputStream in;
        private long left;
        private boolean done;

        Chunked(InputStream in) {
            this.in = in;
        }

        private boolean next() throws IOException {
            if (done) return false;
            if (left == 0) {
                String size = readLine(in, new int[] {0});
                if (size.isEmpty()) size = readLine(in, new int[] {0}); // CRLF after the previous chunk
                int semi = size.indexOf(';');
                try {
                    left = Long.parseLong((semi >= 0 ? size.substring(0, semi) : size).trim(), 16);
                } catch (NumberFormatException e) {
                    throw new IOException("malformed chunk size");
                }
                if (left == 0) {
                    done = true;
                    return false;
                }
            }
            return true;
        }

        @Override
        public int read() throws IOException {
            if (!next()) return -1;
            int c = in.read();
            if (c < 0) throw new EOFException("truncated chunk");
            left--;
            return c;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (!next()) return -1;
            int n = in.read(b, off, (int) Math.min(len, left));
            if (n < 0) throw new EOFException("truncated chunk");
            left -= n;
            return n;
        }
    }
}
