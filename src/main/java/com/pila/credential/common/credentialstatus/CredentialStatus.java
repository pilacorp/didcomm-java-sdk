package com.pila.credential.common.credentialstatus;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URI;
import com.pila.credential.common.util.BoundedHttp;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.Base64;
import java.util.zip.GZIPInputStream;

/**
 * W3C bitstring status list check (Go {@code credentialstatus.FetchAndCheckRevocation} / {@code IsRevoked}).
 * The status list endpoint returns {@code {"data": <StatusListCredential>}}; {@code encodedList} is
 * base64url(gzip(bitstring)), bit {@code i} is {@code byte[i/8] >> (i%8) & 1}.
 */
public final class CredentialStatus {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final int MAX_RESPONSE_BYTES = 32 << 20;
    private static final int MAX_BITSTRING_BYTES = 16 << 20;
    private static final HttpClient HTTP = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(10)).build();

    /** Fetches the raw status list credential response for a URL. */
    @FunctionalInterface
    public interface Fetcher {
        byte[] fetch(String url) throws Exception;
    }

    private CredentialStatus() {
    }

    public static byte[] httpFetch(String url) throws Exception {
        if (url == null || url.isEmpty()) {
            throw new Exception("statusListCredential URL is empty");
        }
        // Go: http.Client{Timeout: 10s} bounds the whole exchange and follows up to 10 redirects (https to http too).
        BoundedHttp.Response resp = BoundedHttp.get(HTTP, URI.create(url), Map.of(), Duration.ofSeconds(10), 10,
                MAX_RESPONSE_BYTES, null);
        if (resp.status() != 200) {
            throw new Exception("status list credential API returned non-200 status: " + resp.status());
        }
        return resp.body();
    }

    public static boolean fetchAndCheckRevocation(String statusListCredentialURL, int position, Fetcher fetcher)
            throws Exception {
        Fetcher f = fetcher != null ? fetcher : CredentialStatus::httpFetch;
        byte[] body = f.fetch(statusListCredentialURL);
        JsonNode subject = MAPPER.readTree(body).path("data").path("credentialSubject");
        return isRevoked(position, subject.path("statusPurpose").asText(""), subject.path("encodedList").asText(""));
    }

    /** Only {@code revocation} lists decide revocation; other purposes (e.g. suspension) report false, like Go. */
    public static boolean isRevoked(int position, String statusPurpose, String encodedList) throws Exception {
        if (!"revocation".equals(statusPurpose)) {
            return false;
        }
        byte[] bits = decompress(Base64.getUrlDecoder().decode(encodedList));
        int max = bits.length * 8 - 1;
        if (position < 0 || position > max) {
            throw new Exception("position " + position + " is out of range for bitstring of length " + bits.length
                    + " (max position: " + max + ")");
        }
        return ((bits[position / 8] >> (position % 8)) & 1) == 1;
    }

    private static byte[] decompress(byte[] gz) throws Exception {
        try (InputStream in = new GZIPInputStream(new ByteArrayInputStream(gz))) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
                if (out.size() > MAX_BITSTRING_BYTES) {
                    throw new Exception("status list bitstring exceeds " + MAX_BITSTRING_BYTES + " bytes");
                }
            }
            return out.toByteArray();
        }
    }
}
