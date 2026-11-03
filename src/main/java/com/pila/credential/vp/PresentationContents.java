package com.pila.credential.vp;

import com.pila.credential.vc.Credential;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public class PresentationContents {
    private List<Object> context = new ArrayList<>();
    private String id;
    private List<String> types = new ArrayList<>();
    private String holder;
    private Instant validFrom;
    private Instant validUntil;
    private List<Credential> verifiableCredentials = new ArrayList<>();

    public List<Object> getContext() {
        return context;
    }

    public void setContext(List<Object> context) {
        this.context = context != null ? context : new ArrayList<>();
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
        this.types = types != null ? types : new ArrayList<>();
    }

    public String getHolder() {
        return holder;
    }

    public void setHolder(String holder) {
        this.holder = holder;
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

    public List<Credential> getVerifiableCredentials() {
        return verifiableCredentials;
    }

    public void setVerifiableCredentials(List<Credential> verifiableCredentials) {
        this.verifiableCredentials = verifiableCredentials != null ? verifiableCredentials : new ArrayList<>();
    }
}
