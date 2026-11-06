package com.pila.credential.vcanchor;

/** Application-provided persistence. Implementations throw {@link VcAnchorException.BatchConflict} / BatchNotFound. */
public interface Store {
    /** Idempotent for the same content, BatchConflict for different content under the same key. */
    void saveBatch(StoredBatch batch);

    /** Returns a copy; throws BatchNotFound (or returns null, which Manager also treats as not found). */
    StoredBatch getBatch(String issuerDid, String externalTreeId);

    void markAnchored(String issuerDid, String externalTreeId, String txHash);
}
