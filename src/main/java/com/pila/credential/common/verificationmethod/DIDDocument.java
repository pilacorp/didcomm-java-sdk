package com.pila.credential.common.verificationmethod;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Map;

/**
 * DIDDocument represents the structure of a resolved DID Document.
 */
@Getter
@Setter
public class DIDDocument {
    @JsonProperty("@context")
    private List<String> context;

    @JsonProperty("id")
    private String id;

    @JsonProperty("verificationMethod")
    private List<VerificationMethodEntry> verificationMethod;

    @JsonProperty("authentication")
    private List<String> authentication;

    @JsonProperty("assertionMethod")
    private List<String> assertionMethod;

    @JsonProperty("controller")
    private Object controller;

    @JsonProperty("didDocumentMetadata")
    private Map<String, Object> didDocumentMetadata;
}
