package com.pila.credential.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Proof represents a Linked Data Proof for a Verifiable Credential.
 */
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

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getCreated() {
        return created;
    }

    public void setCreated(String created) {
        this.created = created;
    }

    public String getVerificationMethod() {
        return verificationMethod;
    }

    public void setVerificationMethod(String verificationMethod) {
        this.verificationMethod = verificationMethod;
    }

    public String getProofPurpose() {
        return proofPurpose;
    }

    public void setProofPurpose(String proofPurpose) {
        this.proofPurpose = proofPurpose;
    }

    public String getProofValue() {
        return proofValue;
    }

    public void setProofValue(String proofValue) {
        this.proofValue = proofValue;
    }

    public String getJws() {
        return jws;
    }

    public void setJws(String jws) {
        this.jws = jws;
    }

    public String[] getDisclosures() {
        return disclosures;
    }

    public void setDisclosures(String[] disclosures) {
        this.disclosures = disclosures;
    }

    public String getCryptosuite() {
        return cryptosuite;
    }

    public void setCryptosuite(String cryptosuite) {
        this.cryptosuite = cryptosuite;
    }

    public String getChallenge() {
        return challenge;
    }

    public void setChallenge(String challenge) {
        this.challenge = challenge;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }
}
