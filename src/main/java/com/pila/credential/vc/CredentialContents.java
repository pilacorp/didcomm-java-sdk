package com.pila.credential.vc;

import lombok.Data;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * CredentialContents represents the structured contents of a Credential.
 */
@Data
public class CredentialContents {
    private List<Object> context; // JSON-LD contexts
    private String id; // Credential identifier
    private List<String> types; // Credential types
    private String issuer; // Issuer identifier
    private Instant validFrom; // Issuance date
    private Instant validUntil; // Expiration date
    private List<Status> credentialStatus; // Credential status entries
    private List<Subject> subject; // Credential subjects
    private List<Schema> schemas; // Credential schemas

    public CredentialContents() {
        this.context = new ArrayList<>();
        this.types = new ArrayList<>();
        this.credentialStatus = new ArrayList<>();
        this.subject = new ArrayList<>();
        this.schemas = new ArrayList<>();
    }
}
