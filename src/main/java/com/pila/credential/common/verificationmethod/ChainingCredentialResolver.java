package com.pila.credential.common.verificationmethod;

import java.util.Arrays;
import java.util.List;

/**
 * Tries resolvers in order (e.g. did:key offline, then HTTP DID API).
 */
public final class ChainingCredentialResolver implements CredentialResolver {

    private final List<CredentialResolver> chain;

    public ChainingCredentialResolver(CredentialResolver... resolvers) {
        if (resolvers == null || resolvers.length == 0) {
            throw new IllegalArgumentException("at least one resolver is required");
        }
        this.chain = List.copyOf(Arrays.asList(resolvers));
    }

    @Override
    public DIDDocument resolveDocument(String did) throws Exception {
        Exception last = null;
        for (CredentialResolver resolver : chain) {
            try {
                return resolver.resolveDocument(did);
            } catch (Exception e) {
                last = e;
            }
        }
        if (last != null) {
            throw last;
        }
        throw new Exception("DID '" + did + "' could not be resolved");
    }
}
