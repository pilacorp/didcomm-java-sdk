package com.pila.credential.common.verificationmethod;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

/**
 * VerificationMethodEntry represents a single verification method in a DID
 * Document.
 */
@Data
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
}
