package com.pila.credential.common.verificationmethod;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * VerificationMethodEntry represents a single verification method in a DID Document.
 */
public class VerificationMethodEntry {
    @JsonProperty("id")
    private String id;

    @JsonProperty("type")
    private String type;

    @JsonProperty("controller")
    private String controller;

    @JsonProperty("publicKeyHex")
    private String publicKeyHex;

    @JsonProperty("publicKeyJwk")
    private JWK publicKeyJwk;

    @JsonProperty("publicKeyMultibase")
    private String publicKeyMultibase;

    @JsonProperty("revoked")
    private String revoked;

    @JsonProperty("revocationReason")
    private String revocationReason;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getController() {
        return controller;
    }

    public void setController(String controller) {
        this.controller = controller;
    }

    public String getPublicKeyHex() {
        return publicKeyHex;
    }

    public void setPublicKeyHex(String publicKeyHex) {
        this.publicKeyHex = publicKeyHex;
    }

    public JWK getPublicKeyJwk() {
        return publicKeyJwk;
    }

    public void setPublicKeyJwk(JWK publicKeyJwk) {
        this.publicKeyJwk = publicKeyJwk;
    }

    public String getPublicKeyMultibase() {
        return publicKeyMultibase;
    }

    public void setPublicKeyMultibase(String publicKeyMultibase) {
        this.publicKeyMultibase = publicKeyMultibase;
    }

    public String getRevoked() {
        return revoked;
    }

    public void setRevoked(String revoked) {
        this.revoked = revoked;
    }

    public String getRevocationReason() {
        return revocationReason;
    }

    public void setRevocationReason(String revocationReason) {
        this.revocationReason = revocationReason;
    }
}
