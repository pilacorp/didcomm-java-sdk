package com.pila.credential.vccontract;

import java.util.ArrayList;
import java.util.List;

/** Merkle proof components for the deprecated on-chain verifyVC path. */
public class VerifyRequest {
    /** Issuer's Ethereum address (0x...). */
    public String issuerAddress;
    public long treeIndex;
    /** VC hash as 32-byte hex, with or without 0x. */
    public String leaf;
    /** Ordered sibling hashes; empty for a single-leaf tree. */
    public List<String> proof = new ArrayList<>();

    /** Checks the request is well-formed before hitting the chain; throws IllegalArgumentException. */
    public void validate() {
        Validation.validateProofFields(issuerAddress, leaf, proof);
    }
}
