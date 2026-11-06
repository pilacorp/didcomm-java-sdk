package com.pila.credential.vc;

import com.pila.credential.common.verificationmethod.CredentialResolver;
import com.pila.credential.common.verificationmethod.VerificationMethodResolver;

/**
 * Configuration for credential processing.
 *
 * <p>Presentations ({@code com.pila.credential.vp}) read the same defaults through
 * {@link com.pila.credential.vp.PresentationConfig} so {@code vp.init} stays separate from {@code vc.init}
 * like Go; this class only holds the VC side.
 */
public class CredentialConfig {
    public static final String DEFAULT_BASE_URL = "https://api.ndadid.vn/api/v1/did";
    private static String baseURL = DEFAULT_BASE_URL;
    private static CredentialResolver documentResolver;

    /**
     * Initializes the package with a base URL.
     * 
     * @param baseURL The base URL for DID resolution
     */
    public static void init(String baseURL) {
        if (baseURL != null && !baseURL.isEmpty()) {
            CredentialConfig.baseURL = baseURL;
        }
    }

    /**
     * Gets the current base URL.
     * 
     * @return The base URL
     */
    public static String getBaseURL() {
        return baseURL;
    }

    /**
     * Optional injected resolver for offline verification and tests.
     */
    public static void setDocumentResolver(CredentialResolver resolver) {
        documentResolver = resolver;
    }

    /** The resolver injected with {@link #setDocumentResolver}, or null. */
    public static CredentialResolver getInjectedResolver() {
        return documentResolver;
    }

    public static CredentialResolver getDocumentResolver() {
        if (documentResolver != null) {
            return documentResolver;
        }
        return resolverFor(baseURL);
    }

    /**
     * Default resolver: the HTTP DID API at {@code didBaseURL} (Go {@code NewHTTPResolver}). Offline
     * {@code did:key} resolution is opt-in: chain {@code DidKeyP256Resolver} yourself or pass
     * {@code withResolver(...)}.
     */
    public static CredentialResolver resolverFor(String didBaseURL) {
        return new VerificationMethodResolver(didBaseURL);
    }
}
