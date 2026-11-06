package com.pila.credential.common.processor;

import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.JsonLdErrorCode;
import com.apicatalog.jsonld.document.Document;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.jsonld.loader.DocumentLoaderOptions;
import com.apicatalog.jsonld.loader.SchemeRouter;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * JSON-LD DocumentLoader that resolves well-known context/vocab IRIs to local
 * classpath copies first, then falls back to the default loader (network).
 *
 * Classpath layout:
 *  - Known contexts: contexts/<file>
 *    e.g. contexts/w3c.credential.v2.json
 *  - Conventional: contexts/<host>/<path>.jsonld
 *    e.g. contexts/www.w3.org/ns/credentials/v2.jsonld
 */
public final class LocalContextDocumentLoader implements DocumentLoader {

    private static final String CLASSPATH_PREFIX = "contexts/";

    // Map remote URL -> classpath resource under contexts/
    private static final Map<String, String> WELL_KNOWN_CONTEXTS = Map.ofEntries(
            Map.entry("https://www.w3.org/2018/credentials/v1", CLASSPATH_PREFIX + "w3c.credential.v1.json"),
            Map.entry("https://www.w3.org/2018/credentials/v1.jsonld", CLASSPATH_PREFIX + "w3c.credential.v1.json"),
            Map.entry("https://www.w3.org/ns/credentials/v2", CLASSPATH_PREFIX + "w3c.credential.v2.json"),
            Map.entry("https://www.w3.org/ns/credentials/v2.jsonld", CLASSPATH_PREFIX + "w3c.credential.v2.json"),
            Map.entry("https://www.w3.org/ns/credentials/examples/v2", CLASSPATH_PREFIX + "w3c.credential.examples.v2.json"),
            Map.entry("https://www.w3.org/ns/credentials/examples/v2.jsonld", CLASSPATH_PREFIX + "w3c.credential.examples.v2.json"),
            Map.entry("https://w3id.org/security/data-integrity/v2", CLASSPATH_PREFIX + "w3c.security.data-integrity.v2.json"),
            Map.entry("https://w3id.org/citizenship/v4rc1", CLASSPATH_PREFIX + "w3c.citizenship.v4rc1.json"),
            Map.entry("https://w3id.org/citizenship/v4rc1.jsonld", CLASSPATH_PREFIX + "w3c.citizenship.v4rc1.json"),
            Map.entry("https://w3id.org/security/v1", CLASSPATH_PREFIX + "w3c.security.v1.json"),
            Map.entry("https://w3id.org/security/v2", CLASSPATH_PREFIX + "w3c.security.v2.json"),
            Map.entry("https://w3id.org/security/suites/secp256k1-2019/v1",
                    CLASSPATH_PREFIX + "w3c.security.secp256k1-2019.v1.json")
    );

    private final DocumentLoader fallback;

    public LocalContextDocumentLoader() {
        this(SchemeRouter.defaultInstance());
    }

    public LocalContextDocumentLoader(DocumentLoader fallback) {
        this.fallback = Objects.requireNonNull(fallback, "fallback");
    }

    @Override
    public Document loadDocument(URI url, DocumentLoaderOptions options) throws JsonLdError {
        Objects.requireNonNull(url, "url must not be null");
        byte[] local = localBytes(url);
        if (local != null) return documentOf(url, local);
        return fallback.loadDocument(url, options);
    }

    /** Bundled bytes for a well-known or conventional classpath context, or null when there are none. */
    static byte[] localBytes(URI url) throws JsonLdError {
        String known = WELL_KNOWN_CONTEXTS.get(url.toString());
        if (known != null) return readClasspath(known);
        Optional<String> conventional = toConventionalClasspathPath(url);
        return conventional.isPresent() ? readClasspath(conventional.get()) : null;
    }

    static Document documentOf(URI url, byte[] data) throws JsonLdError {
        JsonDocument doc = JsonDocument.of(new java.io.ByteArrayInputStream(data));
        doc.setDocumentUrl(url);
        doc.setContextUrl(url);
        return doc;
    }

    private static byte[] readClasspath(String resourcePath) throws JsonLdError {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        try (InputStream in = cl.getResourceAsStream(resourcePath)) {
            return in == null ? null : in.readAllBytes();
        } catch (IOException e) {
            throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED, e.getMessage());
        }
    }

    private static Optional<String> toConventionalClasspathPath(URI url) {
        String host = url.getHost();
        String path = url.getPath();

        if (host == null || host.isBlank()) return Optional.empty();
        if (path == null || path.isBlank() || "/".equals(path)) return Optional.empty();

        // strip leading '/'
        if (path.startsWith("/")) path = path.substring(1);

        if (!path.endsWith(".jsonld")) path = path + ".jsonld";

        return Optional.of(CLASSPATH_PREFIX + host + "/" + path);
    }
}
