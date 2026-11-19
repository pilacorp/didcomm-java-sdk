package com.pila.credential.vcanchor;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Batch building and local receipt verification (Go vcanchor/batch.go, verify.go). */
public final class VcAnchor {
    public static final String HASH_SCHEME = "keccak256-sorted-pairs-no-leaf-hash-v1";
    /** Also the cap Authen Service enforces on a submitted root. */
    public static final int MAX_LEAVES_PER_BATCH = 10000;

    private VcAnchor() {
    }

    public static Batch buildBatch(BatchInput input) {
        if (input.issuerDid == null || input.issuerDid.isEmpty()) {
            throw new IllegalArgumentException("issuer_did is required");
        }
        if (input.externalTreeId == null || input.externalTreeId.isEmpty()) {
            throw new IllegalArgumentException("external_tree_id is required");
        }
        if (input.vcHashes == null || input.vcHashes.isEmpty()) {
            throw new IllegalArgumentException("vc_hashes is required");
        }
        if (input.vcHashes.size() > MAX_LEAVES_PER_BATCH) {
            throw new IllegalArgumentException("too many vc_hashes: " + input.vcHashes.size()
                    + " exceeds max " + MAX_LEAVES_PER_BATCH + " per batch");
        }
        List<byte[]> leaves = new ArrayList<>(input.vcHashes.size());
        Map<String, Integer> byHash = new HashMap<>();
        for (String h : input.vcHashes) {
            String n = Hashes.normalize32(h);
            if (byHash.containsKey(n)) {
                throw new IllegalArgumentException("duplicate vc_hash " + n);
            }
            byHash.put(n, leaves.size());
            leaves.add(Hashes.raw(n));
        }
        return new Batch(input.issuerDid, input.externalTreeId, Hashes.hex(Merkle.root(leaves)), leaves.size(),
                Hashes.hex(Merkle.digestLeaves(leaves)), byHash, leaves);
    }

    /**
     * Checks that the receipt's vc_hash and proof fold to the anchored root with the right proof length.
     * anchoredRoot and anchoredLeafCount must come from the anchored root record (chain or Authen Service),
     * never from the receipt: the receipt is the thing under test.
     *
     * @return false for a bad receipt; throws for bad input or a missing anchored leaf count.
     */
    public static boolean verifyReceiptLocal(Receipt receipt, String anchoredRoot, int anchoredLeafCount) {
        if (!HASH_SCHEME.equals(receipt.hashScheme)) {
            throw new IllegalArgumentException("unsupported hash_scheme \"" + receipt.hashScheme + "\"");
        }
        byte[] leaf = Hashes.raw(Hashes.normalize32(receipt.vcHash));
        String receiptRoot = Hashes.normalize32(receipt.root);
        String anchored;
        try {
            anchored = Hashes.normalize32(anchoredRoot);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("invalid anchored root: " + e.getMessage(), e);
        }
        if (!receiptRoot.equals(anchored)) {
            return false;
        }
        if (anchoredLeafCount <= 0) {
            throw new IllegalArgumentException("anchored leaf_count is required");
        }
        if (receipt.leafCount != anchoredLeafCount || receipt.proof.size() != Merkle.proofLen(anchoredLeafCount)) {
            return false;
        }
        List<byte[]> proof = new ArrayList<>();
        for (int i = 0; i < receipt.proof.size(); i++) {
            try {
                proof.add(Hashes.raw(Hashes.normalize32(receipt.proof.get(i))));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("invalid proof[" + i + "]: " + e.getMessage(), e);
            }
        }
        return Merkle.verify(leaf, proof, Hashes.raw(anchored));
    }

    /** True when a retry of the same batch; false is a genuine collision (Store throws BatchConflict). */
    public static boolean sameBatchContent(StoredBatch a, StoredBatch b) {
        return a.issuerDid.equals(b.issuerDid) && a.externalTreeId.equals(b.externalTreeId)
                && a.root.equals(b.root) && a.leafCount == b.leafCount && a.hashScheme.equals(b.hashScheme)
                && a.leavesDigest.equals(b.leavesDigest);
    }
}
