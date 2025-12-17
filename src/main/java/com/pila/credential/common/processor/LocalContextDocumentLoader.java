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
    private static final Map<String, String> WELL_KNOWN_CONTEXTS = Map.of(
            "https://www.w3.org/ns/credentials/v2", CLASSPATH_PREFIX + "w3c.credential.v2.json",
            "https://www.w3.org/ns/credentials/v2.jsonld", CLASSPATH_PREFIX + "w3c.credential.v2.json",
            "https://www.w3.org/ns/credentials/examples/v2", CLASSPATH_PREFIX + "w3c.credential.examples.v2.json",
            "https://www.w3.org/ns/credentials/examples/v2.jsonld", CLASSPATH_PREFIX + "w3c.credential.examples.v2.json"
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

        // 1) Known contexts
        String known = WELL_KNOWN_CONTEXTS.get(url.toString());
        if (known != null) {
            Document local = tryClasspath(url, known);
            if (local != null) return local;
            return fallback.loadDocument(url, options);
        }

        // 2) Conventional contexts/<host>/<path>.jsonld
        Optional<String> conventional = toConventionalClasspathPath(url);
        if (conventional.isPresent()) {
            Document local = tryClasspath(url, conventional.get());
            if (local != null) return local;
        }

        // 3) Fallback (network)
        return fallback.loadDocument(url, options);
    }

    private Document tryClasspath(URI url, String resourcePath) throws JsonLdError {
        try (InputStream in = openClasspath(resourcePath)) {
            if (in == null) return null;

            JsonDocument doc = JsonDocument.of(in);
            doc.setDocumentUrl(url);
            doc.setContextUrl(url);
            return doc;
        } catch (IOException e) {
            throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED, e.getMessage());
        }
    }

    private InputStream openClasspath(String resourcePath) {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        return cl.getResourceAsStream(resourcePath);
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
