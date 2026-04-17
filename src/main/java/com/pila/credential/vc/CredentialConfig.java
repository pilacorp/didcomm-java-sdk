package com.pila.credential.vc;

import com.pila.credential.common.verificationmethod.VerificationMethodResolver;
import com.pila.credential.common.verificationmethod.VerificationMethodResolverProvider;

/**
 * Configuration for credential processing.
 */
public class CredentialConfig {
    private static String baseURL = "https://auth-dev.pila.vn/api/v1/did";
    private static volatile VerificationMethodResolverProvider verificationMethodResolverProvider;
    private static volatile CredentialStatusProvider credentialStatusProvider;

    /**
     * Initializes the package with a base URL.
     * 
     * @param baseURL The base URL for DID resolution
     */
    public static void init(String baseURL) {
        if (baseURL != null && !baseURL.isEmpty()) {
            CredentialConfig.baseURL = baseURL;
            CredentialConfig.verificationMethodResolverProvider = new VerificationMethodResolver(baseURL);
        }
    }

    /**
     * Initializes the package with a custom verification method resolver.
     *
     * @param resolverProvider custom resolver implementation
     */
    public static void init(VerificationMethodResolverProvider resolverProvider) {
        if (resolverProvider != null) {
            CredentialConfig.verificationMethodResolverProvider = resolverProvider;
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
     * Gets the current verification method resolver provider.
     *
     * @return the active verification method resolver provider
     */
    public static VerificationMethodResolverProvider getVerificationMethodResolverProvider() {
        return verificationMethodResolverProvider;
    }

    /**
     * Sets the verification method resolver provider.
     *
     * @param resolverProvider the resolver provider to use
     */
    public static void setVerificationMethodResolverProvider(VerificationMethodResolverProvider resolverProvider) {
        if (resolverProvider != null) {
            verificationMethodResolverProvider = resolverProvider;
        }
    }

    /**
     * Sets the credential status provider.
     *
     * @param statusProvider the provider to use for status / revocation checks
     */
    public static void setCredentialStatusProvider(CredentialStatusProvider statusProvider) {
        credentialStatusProvider = statusProvider;
    }

    /**
     * Gets the current credential status provider.
     *
     * @return the active credential status provider, or null if none is configured
     */
    public static CredentialStatusProvider getCredentialStatusProvider() {
        return credentialStatusProvider;
    }
}
