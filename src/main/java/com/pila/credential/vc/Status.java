package com.pila.credential.vc;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Status represents the credentialStatus field as per W3C Verifiable Credentials.
 */
public class Status {
    @JsonProperty("id")
    private String id;

    @JsonProperty("type")
    private String type;

    @JsonProperty("statusPurpose")
    private String statusPurpose;

    @JsonProperty("statusListIndex")
    private String statusListIndex;

    @JsonProperty("statusListCredential")
    private String statusListCredential;

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

    public String getStatusPurpose() {
        return statusPurpose;
    }

    public void setStatusPurpose(String statusPurpose) {
        this.statusPurpose = statusPurpose;
    }

    public String getStatusListIndex() {
        return statusListIndex;
    }

    public void setStatusListIndex(String statusListIndex) {
        this.statusListIndex = statusListIndex;
    }

    public String getStatusListCredential() {
        return statusListCredential;
    }

    public void setStatusListCredential(String statusListCredential) {
        this.statusListCredential = statusListCredential;
    }
}
