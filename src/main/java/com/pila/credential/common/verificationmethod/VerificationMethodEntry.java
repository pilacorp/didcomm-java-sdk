package com.pila.credential.common.verificationmethod;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

/**
 * VerificationMethodEntry represents a single verification method in a DID Document.
 */
@Getter
@Setter
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
}
