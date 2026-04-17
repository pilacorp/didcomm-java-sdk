package com.pila.credential.vc;

/**
 * Abstraction for resolving credential status / revocation data.
 *
 * Implementations can resolve status list state from HTTP, chain storage,
 * caches, or any other backend without changing credential verification code.
 */
public interface CredentialStatusProvider {
    String resolveStatusList(CredentialData credentialData) throws Exception;
}
