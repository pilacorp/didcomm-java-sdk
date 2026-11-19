package com.pila.credential.vcanchor;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/** Reference Store (Go's test store); thread-safe via a single lock. */
public final class InMemoryStore implements Store {
    private final Map<String, StoredBatch> batches = new HashMap<>();

    private static String key(String issuer, String tree) {
        return issuer + "\0" + tree;
    }

    @Override
    public synchronized void saveBatch(StoredBatch in) {
        StoredBatch batch = in.copy();
        long now = Instant.now().getEpochSecond();
        if (batch.createdAtUnix == 0) {
            batch.createdAtUnix = now;
        }
        batch.lastModifiedUnix = now;
        if (batch.status == null || batch.status.isEmpty()) {
            batch.status = "created";
        }
        String k = key(batch.issuerDid, batch.externalTreeId);
        StoredBatch existing = batches.get(k);
        if (existing != null) {
            if (!VcAnchor.sameBatchContent(existing, batch)) {
                throw new VcAnchorException.BatchConflict();
            }
            return;
        }
        batches.put(k, batch);
    }

    @Override
    public synchronized StoredBatch getBatch(String issuerDid, String externalTreeId) {
        StoredBatch b = batches.get(key(issuerDid, externalTreeId));
        if (b == null) {
            throw new VcAnchorException.BatchNotFound();
        }
        return b.copy();
    }

    @Override
    public synchronized void markAnchored(String issuerDid, String externalTreeId, String txHash) {
        if (txHash == null || txHash.isEmpty()) {
            throw new IllegalArgumentException("tx_hash is required");
        }
        StoredBatch b = batches.get(key(issuerDid, externalTreeId));
        if (b == null) {
            throw new VcAnchorException.BatchNotFound();
        }
        long now = Instant.now().getEpochSecond();
        b.txHash = txHash;
        b.status = "anchored";
        b.anchoredAtUnix = now;
        b.lastModifiedUnix = now;
    }
}
