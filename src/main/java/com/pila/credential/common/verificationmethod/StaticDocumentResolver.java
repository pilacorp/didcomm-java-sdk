package com.pila.credential.common.verificationmethod;

import java.util.HashMap;
import java.util.Map;

/**
 * In-memory DID documents for offline verification and interop tests.
 */
public final class StaticDocumentResolver implements CredentialResolver {

    private final Map<String, DIDDocument> documents = new HashMap<>();

    public StaticDocumentResolver register(DIDDocument doc) {
        if (doc == null || doc.getId() == null || doc.getId().isEmpty()) {
            throw new IllegalArgumentException("DID document id is required");
        }
        documents.put(doc.getId(), doc);
        return this;
    }

    @Override
    public DIDDocument resolveDocument(String did) throws Exception {
        DIDDocument doc = documents.get(did);
        if (doc == null) {
            throw new Exception("DID '" + did + "' not found in static resolver");
        }
        return doc;
    }
}
