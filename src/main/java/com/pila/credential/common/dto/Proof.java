package com.pila.credential.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

/**
 * Proof represents a Linked Data Proof for a Verifiable Credential.
 */
@Data
public class Proof {
    @JsonProperty("type")
    private String type;

    @JsonProperty("created")
    private String created;

    @JsonProperty("verificationMethod")
    private String verificationMethod;

    @JsonProperty("proofPurpose")
    private String proofPurpose;

    @JsonProperty("proofValue")
    private String proofValue;

    @JsonProperty("jws")
    private String jws;

    @JsonProperty("disclosures")
    private String[] disclosures;

    @JsonProperty("cryptosuite")
    private String cryptosuite;

    @JsonProperty("challenge")
    private String challenge;

    @JsonProperty("domain")
    private String domain;

    // For JWT proof
    private byte[] signature;
}
