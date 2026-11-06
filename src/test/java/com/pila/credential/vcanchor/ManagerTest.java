package com.pila.credential.vcanchor;

import static com.pila.credential.vcanchor.VcAnchorTest.*;
import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.junit.jupiter.api.Test;

class ManagerTest {
    @Test
    void persistsBatchAndGeneratesReceiptFromStore() {
        Manager m = new Manager(new InMemoryStore());
        List<String> hashes = seq(3);
        Batch b = m.createBatch(new BatchInput(ISSUER, "app-tree-001", hashes));
        m.validateStoredBatch(b.issuerDid, b.externalTreeId);
        m.markAnchored(b.issuerDid, b.externalTreeId, "0xtx");
        Receipt r = m.generateReceipt(b.issuerDid, b.externalTreeId, hashes.get(1));
        assertEquals("0xtx", r.txHash);
        assertTrue(VcAnchor.verifyReceiptLocal(r, b.root, 3));
    }

    @Test
    void storeRejectsSameTreeWithDifferentDigestButAcceptsRetry() {
        InMemoryStore store = new InMemoryStore();
        StoredBatch first = build("t", seq(1)).toStored();
        StoredBatch second = build("t", List.of(h(2))).toStored();
        store.saveBatch(first);
        store.saveBatch(first);
        assertThrows(VcAnchorException.BatchConflict.class, () -> store.saveBatch(second));
    }

    @Test
    void storeContractRoundTrip() {
        InMemoryStore store = new InMemoryStore();
        Batch b = build("t", seq(2));
        store.saveBatch(b.toStored());
        store.markAnchored(b.issuerDid, b.externalTreeId, "0xtx");
        StoredBatch loaded = store.getBatch(b.issuerDid, b.externalTreeId);
        assertEquals(b.root, loaded.root);
        assertEquals("0xtx", loaded.txHash);
        assertEquals("anchored", loaded.status);
        assertThrows(VcAnchorException.BatchNotFound.class, () -> store.getBatch(ISSUER, "nope"));
        assertThrows(VcAnchorException.BatchNotFound.class, () -> store.markAnchored(ISSUER, "nope", "0xtx"));
    }

    @Test
    void generateReceiptRequiresMarkAnchored() {
        Manager m = new Manager(new InMemoryStore());
        List<String> hashes = seq(2);
        m.createBatch(new BatchInput(ISSUER, "unanchored", hashes));
        assertThrows(IllegalStateException.class, () -> m.generateReceipt(ISSUER, "unanchored", hashes.get(0)));
        assertThrows(IllegalArgumentException.class, () -> m.markAnchored(ISSUER, "unanchored", ""));
        m.markAnchored(ISSUER, "unanchored", "0xtx");
        assertEquals("0xtx", m.generateReceipt(ISSUER, "unanchored", hashes.get(0)).txHash);
    }

    @Test
    void markAnchoredOnUnknownBatchAndNullStoreMiss() {
        assertThrows(VcAnchorException.BatchNotFound.class,
                () -> new Manager(new InMemoryStore()).markAnchored(ISSUER, "x", "0xtx"));
        Store nullStore = new Store() {
            public void saveBatch(StoredBatch b) {
            }

            public StoredBatch getBatch(String i, String t) {
                return null;
            }

            public void markAnchored(String i, String t, String tx) {
                fail("must not be reached");
            }
        };
        Manager m = new Manager(nullStore);
        assertThrows(VcAnchorException.BatchNotFound.class, () -> m.markAnchored(ISSUER, "x", "0xtx"));
        assertThrows(VcAnchorException.BatchNotFound.class, () -> m.generateReceipt(ISSUER, "x", h(1)));
        assertThrows(IllegalStateException.class, () -> new Manager(null).createBatch(null));
    }

    @Test
    void validateStoredBatchDetectsTampering() {
        InMemoryStore store = new InMemoryStore();
        Manager m = new Manager(store);
        m.createBatch(new BatchInput(ISSUER, "t", seq(3)));
        Store tampering = new Store() {
            public void saveBatch(StoredBatch b) {
            }

            public StoredBatch getBatch(String i, String t) {
                StoredBatch s = store.getBatch(i, t);
                s.orderedVcHashes.set(0, s.orderedVcHashes.get(1)); // reorder/rewrite
                s.orderedVcHashes.set(1, h(99));
                return s;
            }

            public void markAnchored(String i, String t, String tx) {
            }
        };
        assertThrows(IllegalStateException.class, () -> new Manager(tampering).validateStoredBatch(ISSUER, "t"));
    }
}
