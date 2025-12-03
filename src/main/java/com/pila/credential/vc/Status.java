package com.pila.credential.vc;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

/**
 * Status represents the credentialStatus field as per W3C Verifiable
 * Credentials.
 */
@Data
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
}
