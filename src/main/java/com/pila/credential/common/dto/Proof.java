package com.pila.credential.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import lombok.Setter;

/**
 * Proof represents a Linked Data Proof for a Verifiable Credential.
 */
@Getter
@Setter
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

    private byte[] signature;

    /**
     * Every property of the proof object this was parsed from, in document order. The proof
     * configuration is the whole proof minus its signature field (Data Integrity 4.4), so
     * verification hashes this, not the typed fields. Null for a proof built in code.
     */
    @JsonIgnore
    private java.util.Map<String, Object> raw;
}
