package com.pila.credential.common.verificationmethod;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

/**
 * DIDDocument represents the structure of a resolved DID Document.
 */
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

    public List<String> getContext() {
        return context;
    }

    public void setContext(List<String> context) {
        this.context = context;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public List<VerificationMethodEntry> getVerificationMethod() {
        return verificationMethod;
    }

    public void setVerificationMethod(List<VerificationMethodEntry> verificationMethod) {
        this.verificationMethod = verificationMethod;
    }

    public List<String> getAuthentication() {
        return authentication;
    }

    public void setAuthentication(List<String> authentication) {
        this.authentication = authentication;
    }

    public List<String> getAssertionMethod() {
        return assertionMethod;
    }

    public void setAssertionMethod(List<String> assertionMethod) {
        this.assertionMethod = assertionMethod;
    }

    public Object getController() {
        return controller;
    }

    public void setController(Object controller) {
        this.controller = controller;
    }

    public Map<String, Object> getDidDocumentMetadata() {
        return didDocumentMetadata;
    }

    public void setDidDocumentMetadata(Map<String, Object> didDocumentMetadata) {
        this.didDocumentMetadata = didDocumentMetadata;
    }
}
