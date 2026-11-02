package com.pila.credential.vc;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * CredentialContents represents the structured contents of a Credential.
 */
public class CredentialContents {
    private List<Object> context;
    private String id;
    private List<String> types;
    private String issuer;
    private Instant validFrom;
    private Instant validUntil;
    private List<Status> credentialStatus;
    private List<Subject> subject;
    private List<Schema> schemas;

    public CredentialContents() {
        this.context = new ArrayList<>();
        this.types = new ArrayList<>();
        this.credentialStatus = new ArrayList<>();
        this.subject = new ArrayList<>();
        this.schemas = new ArrayList<>();
    }

    public List<Object> getContext() {
        return context;
    }

    public void setContext(List<Object> context) {
        this.context = context;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public List<String> getTypes() {
        return types;
    }

    public void setTypes(List<String> types) {
        this.types = types;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public Instant getValidFrom() {
        return validFrom;
    }

    public void setValidFrom(Instant validFrom) {
        this.validFrom = validFrom;
    }

    public Instant getValidUntil() {
        return validUntil;
    }

    public void setValidUntil(Instant validUntil) {
        this.validUntil = validUntil;
    }

    public List<Status> getCredentialStatus() {
        return credentialStatus;
    }

    public void setCredentialStatus(List<Status> credentialStatus) {
        this.credentialStatus = credentialStatus;
    }

    public List<Subject> getSubject() {
        return subject;
    }

    public void setSubject(List<Subject> subject) {
        this.subject = subject;
    }

    public List<Schema> getSchemas() {
        return schemas;
    }

    public void setSchemas(List<Schema> schemas) {
        this.schemas = schemas;
    }
}
