package com.pila.credential.common.processor;

import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.JsonLdErrorCode;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.document.Document;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.jsonld.loader.DocumentLoaderOptions;
import com.apicatalog.jsonld.loader.SchemeRouter;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * A JSON-LD {@link DocumentLoader} that resolves well-known context/vocab IRIs
 * to local copies instead of fetching them over the network.
 *
 * Priority:
 *  1) external context dir (env JSONLD_CONTEXT_DIR or system property jsonld.context.dir)
 *  2) classpath resources under contexts/<host>/<path>
 *  3) fallback to default loader (network)
 */
public final class LocalContextDocumentLoader implements DocumentLoader {

    // If you want to prohibit network calls entirely, set this to false and throw when not resolved locally.
    private final boolean allowRemoteFallback;

    private final Path externalContextDir;
    private final DocumentLoader fallbackLoader;

    private static final String ENV_CONTEXT_DIR = "JSONLD_CONTEXT_DIR";
    private static final String PROP_CONTEXT_DIR = "jsonld.context.dir";
    private static final String CLASSPATH_PREFIX = "contexts";

    // Map “remote URL” -> “classpath resource path”
    // Convention: contexts/<host>/<path>.jsonld
    private static final Map<String, String> WELL_KNOWN_CONTEXTS = Map.of(
            "https://www.w3.org/ns/credentials/v2", "contexts/www.w3.org/ns/credentials/v2.jsonld",
            "https://www.w3.org/ns/credentials/v2.jsonld", "contexts/www.w3.org/ns/credentials/v2.jsonld",
            "https://www.w3.org/ns/credentials/examples/v2", "contexts/www.w3.org/ns/credentials/examples/v2.jsonld",
            "https://www.w3.org/ns/credentials/examples/v2.jsonld", "contexts/www.w3.org/ns/credentials/examples/v2.jsonld"
    );

    public LocalContextDocumentLoader() {
        this(true);
    }

    public LocalContextDocumentLoader(boolean allowRemoteFallback) {
        this(allowRemoteFallback, SchemeRouter.defaultInstance());
    }

    public LocalContextDocumentLoader(boolean allowRemoteFallback, DocumentLoader fallbackLoader) {
        this.allowRemoteFallback = allowRemoteFallback;
        this.externalContextDir = resolveExternalDir().orElse(null);
        this.fallbackLoader = Objects.requireNonNull(fallbackLoader, "fallbackLoader");
    }

    @Override
    public Document loadDocument(final URI url, final DocumentLoaderOptions options) throws JsonLdError {
        Objects.requireNonNull(url, "context url must not be null");

        final String urlString = url.toString();
        final String mappedClasspath = WELL_KNOWN_CONTEXTS.get(urlString);

        // 1) If it's a known context, try external dir -> classpath -> fallback
        if (mappedClasspath != null) {
            try {
                InputStream in = openFromExternalDir(mappedClasspath);
                if (in != null) return buildDocument(url, in);

                in = openFromClasspath(mappedClasspath);
                if (in != null) return buildDocument(url, in);

                return remoteOrThrow(url, options, "Local mapping exists but file not found: " + mappedClasspath);
            } catch (IOException e) {
                throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED, e.getMessage());
            }
        }

        // 2) For other URLs: try generic convention contexts/<host>/<path>(.jsonld?) if you want
        //    (optional, but useful). If not found, fallback.
        final Optional<String> conventional = toConventionalClasspathPath(url);
        if (conventional.isPresent()) {
            try {
                InputStream in = openFromExternalDir(conventional.get());
                if (in != null) return buildDocument(url, in);

                in = openFromClasspath(conventional.get());
                if (in != null) return buildDocument(url, in);
            } catch (IOException e) {
                throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED, e.getMessage());
            }
        }

        // 3) Fallback
        return remoteOrThrow(url, options, "Context not resolved locally: " + urlString);
    }

    private Document remoteOrThrow(URI url, DocumentLoaderOptions options, String message) throws JsonLdError {
        if (!allowRemoteFallback) {
            throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED, message);
        }
        return fallbackLoader.loadDocument(url, options);
    }

    private Document buildDocument(final URI url, final InputStream stream) throws IOException, JsonLdError {
        try (stream) {
            final JsonDocument doc = JsonDocument.of(stream);
            doc.setDocumentUrl(url);
            doc.setContextUrl(url);
            return doc;
        }
    }

    private InputStream openFromClasspath(final String classpathResource) {
        final ClassLoader cl = Thread.currentThread().getContextClassLoader();
        return cl.getResourceAsStream(classpathResource);
    }

    private InputStream openFromExternalDir(final String resourcePath) throws IOException {
        if (externalContextDir == null) return null;

        final Path candidate = externalContextDir.resolve(resourcePath);
        if (Files.exists(candidate) && Files.isRegularFile(candidate)) {
            return Files.newInputStream(candidate);
        }
        return null;
    }

    /**
     * Convert URL to "contexts/<host>/<path>.jsonld" (best-effort).
     * Example:
     *   https://www.w3.org/ns/credentials/v2  -> contexts/www.w3.org/ns/credentials/v2.jsonld
     */
    private static Optional<String> toConventionalClasspathPath(final URI url) throws JsonLdError {
        if (url.getHost() == null || url.getHost().isBlank()) {
            return Optional.empty();
        }
        String path = url.getPath();
        if (path == null || path.isBlank() || "/".equals(path)) {
            return Optional.empty();
        }

        // Normalize: remove leading '/'
        if (path.startsWith("/")) path = path.substring(1);

        // Ensure .jsonld extension
        if (!path.endsWith(".jsonld")) {
            path = path + ".jsonld";
        }

        return Optional.of(CLASSPATH_PREFIX + "/" + url.getHost() + "/" + path);
    }

    private static Optional<Path> resolveExternalDir() {
        // Priority: system property -> env var
        final String prop = System.getProperty(PROP_CONTEXT_DIR);
        if (prop != null && !prop.isBlank()) {
            return Optional.of(Paths.get(prop).toAbsolutePath().normalize());
        }

        final String env = System.getenv(ENV_CONTEXT_DIR);
        if (env != null && !env.isBlank()) {
            return Optional.of(Paths.get(env).toAbsolutePath().normalize());
        }

        return Optional.empty();
    }
}
