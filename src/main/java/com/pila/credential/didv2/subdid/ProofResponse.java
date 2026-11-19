package com.pila.credential.didv2.subdid;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.List;

/** The JSON answer of GET /api/v3/sub-did/{did}/proof (Go subdid.ProofResponse). */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class ProofResponse {
    @JsonProperty("did")
    public String did;
    @JsonProperty("root_did")
    public String rootDid;
    @JsonProperty("tree_index")
    public String treeIndex;
    @JsonProperty("chains")
    public List<ChainProof> chains = new ArrayList<>();

    /** The proof of the Sub-DID's leaf in the last root one chain anchored (Go subdid.ChainProof). */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static final class ChainProof {
        @JsonProperty("chain")
        public String chain;
        @JsonProperty("tx_hash")
        public String txHash;
        @JsonProperty("root")
        public String root;
        @JsonProperty("path")
        public List<String> path = new ArrayList<>();
        @JsonProperty("status")
        public String status;
    }

    public static ProofResponse fromJson(String json) throws Exception {
        ProofResponse p = new ObjectMapper().readValue(json, ProofResponse.class);
        if (p.chains == null) {
            p.chains = new ArrayList<>();
        }
        return p;
    }
}
