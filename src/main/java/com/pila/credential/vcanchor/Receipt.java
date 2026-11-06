package com.pila.credential.vcanchor;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import java.util.List;

/** Snake_case wire format identical to Go's vcanchor.Receipt (tx_hash omitted when empty). */
@JsonPropertyOrder({"issuer_did", "external_tree_id", "vc_hash", "leaf_index", "leaf_count", "root", "proof",
        "tx_hash", "hash_scheme"})
public final class Receipt {
    @JsonProperty("issuer_did") public final String issuerDid;
    @JsonProperty("external_tree_id") public final String externalTreeId;
    @JsonProperty("vc_hash") public final String vcHash;
    @JsonProperty("leaf_index") public final int leafIndex;
    @JsonProperty("leaf_count") public final int leafCount;
    @JsonProperty("root") public final String root;
    @JsonProperty("proof") public final List<String> proof;
    @JsonProperty("tx_hash") @JsonInclude(JsonInclude.Include.NON_EMPTY) public final String txHash;
    @JsonProperty("hash_scheme") public final String hashScheme;

    @JsonCreator
    public Receipt(@JsonProperty("issuer_did") String issuerDid,
            @JsonProperty("external_tree_id") String externalTreeId,
            @JsonProperty("vc_hash") String vcHash,
            @JsonProperty("leaf_index") int leafIndex,
            @JsonProperty("leaf_count") int leafCount,
            @JsonProperty("root") String root,
            @JsonProperty("proof") List<String> proof,
            @JsonProperty("tx_hash") String txHash,
            @JsonProperty("hash_scheme") String hashScheme) {
        this.issuerDid = issuerDid;
        this.externalTreeId = externalTreeId;
        this.vcHash = vcHash;
        this.leafIndex = leafIndex;
        this.leafCount = leafCount;
        this.root = root;
        this.proof = proof == null ? List.of() : proof;
        this.txHash = txHash;
        this.hashScheme = hashScheme;
    }

    /** Copy with a different field set; tests use it to forge receipts. */
    public Receipt with(String vcHash, int leafCount, String root, List<String> proof) {
        return new Receipt(issuerDid, externalTreeId, vcHash, leafIndex, leafCount, root, proof, txHash, hashScheme);
    }
}
