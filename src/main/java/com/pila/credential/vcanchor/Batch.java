package com.pila.credential.vcanchor;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@JsonPropertyOrder({"issuer_did", "external_tree_id", "root", "leaf_count", "hash_scheme", "leaves_digest"})
public final class Batch {
    @JsonProperty("issuer_did") public final String issuerDid;
    @JsonProperty("external_tree_id") public final String externalTreeId;
    @JsonProperty("root") public final String root;
    @JsonProperty("leaf_count") public final int leafCount;
    @JsonProperty("hash_scheme") public final String hashScheme;
    @JsonProperty("leaves_digest") public final String leavesDigest;

    @JsonIgnore final Map<String, Integer> leavesByHash;
    @JsonIgnore final List<byte[]> leaves;

    Batch(String issuerDid, String externalTreeId, String root, int leafCount, String leavesDigest,
            Map<String, Integer> leavesByHash, List<byte[]> leaves) {
        this.issuerDid = issuerDid;
        this.externalTreeId = externalTreeId;
        this.root = root;
        this.leafCount = leafCount;
        this.hashScheme = VcAnchor.HASH_SCHEME;
        this.leavesDigest = leavesDigest;
        this.leavesByHash = leavesByHash;
        this.leaves = leaves;
    }

    public Receipt receipt(String vcHash, String txHash) {
        String normalized = Hashes.normalize32(vcHash);
        Integer idx = leavesByHash.get(normalized);
        if (idx == null) {
            throw new IllegalArgumentException("vc_hash " + normalized + " is not in batch");
        }
        List<String> proof = new ArrayList<>();
        for (byte[] sibling : Merkle.proof(leaves, idx)) {
            proof.add(Hashes.hex(sibling));
        }
        return new Receipt(issuerDid, externalTreeId, normalized, idx, leafCount, root, proof, txHash, hashScheme);
    }

    StoredBatch toStored() {
        List<String> hashes = new ArrayList<>();
        for (byte[] l : leaves) {
            hashes.add(Hashes.hex(l));
        }
        StoredBatch s = new StoredBatch();
        s.issuerDid = issuerDid;
        s.externalTreeId = externalTreeId;
        s.root = root;
        s.leafCount = leafCount;
        s.hashScheme = hashScheme;
        s.leavesDigest = leavesDigest;
        s.orderedVcHashes = hashes;
        s.status = "created";
        return s;
    }
}
