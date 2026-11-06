package com.pila.credential.vcanchor;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.didv2.Hex;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.junit.jupiter.api.Test;

class VcAnchorTest {
    static final String ISSUER = "did:pila:testnet:0xissuer";
    static final ObjectMapper JSON = new ObjectMapper();

    static String h(int n) {
        return String.format("0x%064x", n);
    }

    static List<String> seq(int n) {
        List<String> l = new ArrayList<>();
        for (int i = 1; i <= n; i++) {
            l.add(h(i));
        }
        return l;
    }

    static Batch build(String tree, List<String> hashes) {
        return VcAnchor.buildBatch(new BatchInput(ISSUER, tree, hashes));
    }

    @Test
    void buildBatchGeneratesVerifiableReceipt() {
        List<String> hashes = seq(4);
        Batch b = build("app-tree-001", hashes);
        assertEquals(VcAnchor.HASH_SCHEME, b.hashScheme);
        assertEquals(4, b.leafCount);
        assertTrue(b.root.startsWith("0x") && b.root.length() == 66);
        Receipt r = b.receipt(hashes.get(2), "0xtx");
        assertEquals(2, r.leafIndex);
        assertEquals(2, r.proof.size());
        assertTrue(VcAnchor.verifyReceiptLocal(r, b.root, 4));
    }

    @Test
    void rejectsTamperedLeaf() {
        Batch b = build("t", seq(3));
        Receipt r = b.receipt(h(2), "0xtx");
        Receipt forged = r.with(h(9), r.leafCount, r.root, r.proof);
        assertFalse(VcAnchor.verifyReceiptLocal(forged, b.root, 3));
    }

    @Test
    void rejectsDuplicateHashesAndBadInput() {
        assertThrows(IllegalArgumentException.class,
                () -> build("t", List.of(h(1), h(1).substring(2).toUpperCase())));
        assertThrows(IllegalArgumentException.class, () -> build("", seq(1)));
        assertThrows(IllegalArgumentException.class, () -> build("t", List.of()));
        assertThrows(IllegalArgumentException.class, () -> build("t", List.of("0x12")));
        assertThrows(IllegalArgumentException.class, () -> VcAnchor.buildBatch(new BatchInput("", "t", seq(1))));
        assertThrows(IllegalArgumentException.class, () -> build("t", seq(2)).receipt(h(7), "0xtx"));
    }

    @Test
    void proofLenMatchesGeneratedProofs() {
        for (int n = 1; n <= 40; n++) {
            List<byte[]> leaves = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                byte[] leaf = new byte[32];
                leaf[30] = (byte) (i / 256);
                leaf[31] = (byte) (i % 256);
                leaves.add(leaf);
            }
            for (int idx : new int[] {0, n / 2, n - 1}) {
                assertEquals(Merkle.proof(leaves, idx).size(), Merkle.proofLen(n), "n=" + n + " idx=" + idx);
            }
        }
    }

    @Test
    void receiptCarriesLeafCountAndVerifies() {
        Batch b = build("t", seq(3));
        Receipt r = b.receipt(h(2), "0xtx");
        assertEquals(3, r.leafCount);
        assertTrue(VcAnchor.verifyReceiptLocal(r, b.root, 3));
    }

    @Test
    void rejectsInternalNodeAsLeaf() {
        List<String> hashes = seq(4);
        Batch b = build("app-tree-preimage", hashes);
        Receipt r = b.receipt(hashes.get(0), "0xtx");
        byte[] internal = Merkle.mergeSorted(Hashes.raw(r.vcHash), Hashes.raw(r.proof.get(0)));
        List<String> shortProof = r.proof.subList(1, r.proof.size());
        // test setup guard: without the length check this folds to the root
        List<byte[]> raw = new ArrayList<>();
        shortProof.forEach(s -> raw.add(Hashes.raw(s)));
        assertTrue(Merkle.verify(internal, raw, Hashes.raw(r.root)));
        for (int declared : new int[] {4, 2}) {
            Receipt attempt = r.with(Hashes.hex(internal), declared, r.root, shortProof);
            assertFalse(VcAnchor.verifyReceiptLocal(attempt, b.root, 4), "declared " + declared);
        }
    }

    @Test
    void rejectsReceiptWithoutLeafCount() {
        Receipt r = new Receipt(null, null, h(1), 0, 0, h(1), List.of(), null, VcAnchor.HASH_SCHEME);
        assertThrows(IllegalArgumentException.class, () -> VcAnchor.verifyReceiptLocal(r, r.root, 0));
        assertFalse(VcAnchor.verifyReceiptLocal(r, r.root, 1));
        Receipt badScheme = new Receipt(null, null, h(1), 0, 1, h(1), List.of(), null, "other");
        assertThrows(IllegalArgumentException.class, () -> VcAnchor.verifyReceiptLocal(badScheme, h(1), 1));
    }

    @Test
    void rejectsMoreThanMaxLeaves() {
        List<String> hashes = seq(VcAnchor.MAX_LEAVES_PER_BATCH + 1);
        assertEquals(10000, VcAnchor.MAX_LEAVES_PER_BATCH);
        assertThrows(IllegalArgumentException.class, () -> build("oversized", hashes));
        assertEquals(10000, build("at-cap", hashes.subList(0, 10000)).leafCount);
    }

    @Test
    void rejectsReceiptFromForeignTree() {
        List<String> hashes = seq(4);
        Batch anchored = build("real", hashes);
        List<String> fake = List.of(h(0xf1), h(0xf2), h(0xf3), h(0xf4));
        Batch forged = build("forged", fake);
        Receipt r = forged.receipt(fake.get(0), "0xtx");
        assertTrue(VcAnchor.verifyReceiptLocal(r, forged.root, 4));
        assertFalse(VcAnchor.verifyReceiptLocal(r, anchored.root, 4));
        Receipt lying = r.with(r.vcHash, r.leafCount, anchored.root, r.proof);
        assertFalse(VcAnchor.verifyReceiptLocal(lying, anchored.root, 4));
    }

    @Test
    void wireFormatIsSnakeCaseAndOmitsEmptyTxHash() throws Exception {
        Batch b = build("t", seq(2));
        JsonNode batchJson = JSON.readTree(JSON.writeValueAsString(b));
        assertEquals(List.of("issuer_did", "external_tree_id", "root", "leaf_count", "hash_scheme", "leaves_digest"),
                names(batchJson));
        assertNull(batchJson.get("leaves"));
        Receipt r = b.receipt(h(1), "");
        assertFalse(JSON.readTree(JSON.writeValueAsString(r)).has("tx_hash"));
        Receipt round = JSON.readValue(JSON.writeValueAsString(b.receipt(h(1), "0xtx")), Receipt.class);
        assertEquals("0xtx", round.txHash);
        assertTrue(VcAnchor.verifyReceiptLocal(round, b.root, 2));
    }

    @Test
    void byteExactAgainstGoVectors() throws Exception {
        JsonNode vectors;
        try (InputStream in = getClass().getResourceAsStream("/vcanchor/go-vcanchor-vccontract-vectors.json")) {
            vectors = JSON.readTree(in);
        }
        int checked = 0;
        for (JsonNode v : vectors.get("batches")) {
            List<String> hashes = new ArrayList<>();
            v.get("hashes").forEach(x -> hashes.add(x.asText()));
            Batch b = build("t", hashes);
            assertEquals(v.get("root").asText(), b.root, v.get("kind") + "/" + v.get("n"));
            assertEquals(v.get("leaves_digest").asText(), b.leavesDigest);
            for (JsonNode want : v.get("receipts")) {
                JsonNode got = JSON.readTree(JSON.writeValueAsString(b.receipt(want.get("vc_hash").asText(), "0xtx")));
                assertEquals(want, got);
                assertEquals(names(want), names(got));
                checked++;
            }
        }
        assertTrue(checked > 100);
        assertEquals("0x" + Hex.encode(Merkle.root(List.of(new byte[32]))), Hashes.hex(new byte[32]));
    }

    static List<String> names(JsonNode n) {
        List<String> out = new ArrayList<>();
        for (Iterator<String> it = n.fieldNames(); it.hasNext();) {
            out.add(it.next());
        }
        return out;
    }
}
