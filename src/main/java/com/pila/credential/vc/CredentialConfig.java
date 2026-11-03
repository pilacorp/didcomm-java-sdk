package com.pila.credential.vc;

import com.pila.credential.common.verificationmethod.ChainingCredentialResolver;
import com.pila.credential.common.verificationmethod.CredentialResolver;
import com.pila.credential.common.verificationmethod.DidKeyP256Resolver;
import com.pila.credential.common.verificationmethod.VerificationMethodResolver;

/**
 * Configuration for credential processing.
 */
public class CredentialConfig {
    private static String baseURL = "https://api.ndadid.vn/api/v1/did";
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

    public static CredentialResolver getDocumentResolver() {
        if (documentResolver != null) {
            return documentResolver;
        }
        return resolverFor(baseURL);
    }

    /**
     * Default resolver chain: offline did:key P-256, then HTTP DID API.
     */
    public static CredentialResolver resolverFor(String didBaseURL) {
        return new ChainingCredentialResolver(
                new DidKeyP256Resolver(),
                new VerificationMethodResolver(didBaseURL));
    }
}
