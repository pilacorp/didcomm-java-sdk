package com.pila.credential.vcanchor;

/**
 * Builds trees, keeps them in the application's Store and proves membership. Anchoring itself (handing a
 * root to Authen Service) belongs to the application, which reports the tx hash via {@link #markAnchored}.
 */
public final class Manager {
    private final Store store;

    public Manager(Store store) {
        this.store = store;
    }

    private Store store() {
        if (store == null) {
            throw new IllegalStateException("store is required");
        }
        return store;
    }

    public Batch createBatch(BatchInput input) {
        Store s = store();
        Batch batch = VcAnchor.buildBatch(input);
        s.saveBatch(batch.toStored());
        return batch;
    }

    /** A (null) return from an extension-point Store is a miss reported as success: make it an error. */
    private StoredBatch getBatch(String issuerDid, String externalTreeId) {
        StoredBatch stored = store().getBatch(issuerDid, externalTreeId);
        if (stored == null) {
            throw new VcAnchorException.BatchNotFound(
                    "vcanchor: store returned no batch for " + issuerDid + "/" + externalTreeId
                            + ": vcanchor: batch not found");
        }
        return stored;
    }

    /** Records the tx that anchored this batch's root; unlocks {@link #generateReceipt}. */
    public void markAnchored(String issuerDid, String externalTreeId, String txHash) {
        Store s = store();
        if (txHash == null || txHash.isEmpty()) {
            throw new IllegalArgumentException("tx hash is required");
        }
        StoredBatch stored = getBatch(issuerDid, externalTreeId);
        s.markAnchored(stored.issuerDid, stored.externalTreeId, txHash);
    }

    public Receipt generateReceipt(String issuerDid, String externalTreeId, String vcHash) {
        StoredBatch stored = getBatch(issuerDid, externalTreeId);
        if (stored.txHash == null || stored.txHash.isEmpty()) {
            throw new IllegalStateException("batch " + externalTreeId + " is not anchored");
        }
        // ponytail: rebuilds the tree from ordered hashes per receipt; persist levels for multi-million-leaf trees.
        Batch batch = rebuild(stored);
        ensureMatches(batch, stored);
        return batch.receipt(vcHash, stored.txHash);
    }

    public void validateStoredBatch(String issuerDid, String externalTreeId) {
        StoredBatch stored = getBatch(issuerDid, externalTreeId);
        ensureMatches(rebuild(stored), stored);
    }

    private static Batch rebuild(StoredBatch s) {
        return VcAnchor.buildBatch(new BatchInput(s.issuerDid, s.externalTreeId, s.orderedVcHashes));
    }

    private static void ensureMatches(Batch b, StoredBatch s) {
        if (!b.root.equals(s.root)) {
            throw new IllegalStateException("stored batch root mismatch: got " + b.root + " want " + s.root);
        }
        if (b.leafCount != s.leafCount) {
            throw new IllegalStateException(
                    "stored batch leaf_count mismatch: got " + b.leafCount + " want " + s.leafCount);
        }
        if (!b.hashScheme.equals(s.hashScheme)) {
            throw new IllegalStateException(
                    "stored batch hash_scheme mismatch: got " + b.hashScheme + " want " + s.hashScheme);
        }
        if (!b.leavesDigest.equals(s.leavesDigest)) {
            throw new IllegalStateException(
                    "stored batch leaves_digest mismatch: got " + b.leavesDigest + " want " + s.leavesDigest);
        }
    }
}
