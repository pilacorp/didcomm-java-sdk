package com.pila.credential.vcanchor;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import java.util.ArrayList;
import java.util.List;

/** What a {@link Store} persists. Mutable bean: a Store should hand out copies ({@link #copy()}). */
@JsonPropertyOrder({"issuer_did", "external_tree_id", "root", "leaf_count", "hash_scheme", "leaves_digest",
        "ordered_vc_hashes", "tx_hash", "status", "anchored_at_unix", "created_at_unix", "last_modified_unix"})
public final class StoredBatch {
    @JsonProperty("issuer_did") public String issuerDid;
    @JsonProperty("external_tree_id") public String externalTreeId;
    @JsonProperty("root") public String root;
    @JsonProperty("leaf_count") public int leafCount;
    @JsonProperty("hash_scheme") public String hashScheme;
    @JsonProperty("leaves_digest") public String leavesDigest;
    @JsonProperty("ordered_vc_hashes") public List<String> orderedVcHashes = new ArrayList<>();
    @JsonProperty("tx_hash") @JsonInclude(JsonInclude.Include.NON_EMPTY) public String txHash;
    /** Local lifecycle state: "created", then whatever the Store writes in markAnchored. */
    @JsonProperty("status") public String status;
    @JsonProperty("anchored_at_unix") @JsonInclude(JsonInclude.Include.NON_DEFAULT) public long anchoredAtUnix;
    @JsonProperty("created_at_unix") public long createdAtUnix;
    @JsonProperty("last_modified_unix") public long lastModifiedUnix;

    public StoredBatch copy() {
        StoredBatch c = new StoredBatch();
        c.issuerDid = issuerDid;
        c.externalTreeId = externalTreeId;
        c.root = root;
        c.leafCount = leafCount;
        c.hashScheme = hashScheme;
        c.leavesDigest = leavesDigest;
        c.orderedVcHashes = new ArrayList<>(orderedVcHashes);
        c.txHash = txHash;
        c.status = status;
        c.anchoredAtUnix = anchoredAtUnix;
        c.createdAtUnix = createdAtUnix;
        c.lastModifiedUnix = lastModifiedUnix;
        return c;
    }
}
