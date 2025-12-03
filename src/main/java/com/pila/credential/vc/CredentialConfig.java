package com.pila.credential.vc;

/**
 * Configuration for credential processing.
 */
public class CredentialConfig {
    private static String baseURL = "https://auth-dev.pila.vn/api/v1/did";

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
}
