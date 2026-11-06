package com.pila.credential.vp;

import com.pila.credential.common.verificationmethod.CredentialResolver;
import com.pila.credential.vc.CredentialConfig;

/** Presentation-side package configuration, initialised separately from the VC side (Go {@code vp.Init}). */
public final class PresentationConfig {
    private static String baseURL;

    private PresentationConfig() {
    }

    public static void init(String baseURL) {
        if (baseURL != null && !baseURL.isEmpty()) {
            PresentationConfig.baseURL = baseURL;
        }
    }

    /** vp base URL; falls back to the VC default until {@link #init} is called. */
    public static String getBaseURL() {
        return baseURL != null ? baseURL : CredentialConfig.getBaseURL();
    }

    /** The injected global resolver if any, else HTTP against {@link #getBaseURL()}. */
    public static CredentialResolver defaultResolver() {
        CredentialResolver injected = CredentialConfig.getInjectedResolver();
        return injected != null ? injected : CredentialConfig.resolverFor(getBaseURL());
    }
}
