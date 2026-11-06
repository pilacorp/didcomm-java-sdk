package com.pila.credential.vc;

import lombok.Getter;
import lombok.Setter;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * CredentialContents represents the structured contents of a Credential.
 */
@Getter
@Setter
public class CredentialContents {
    private List<Object> context = new ArrayList<>();
    private String id;
    private List<String> types = new ArrayList<>();
    private String issuer;
    private Instant validFrom;
    private Instant validUntil;
    private List<Status> credentialStatus = new ArrayList<>();
    private List<Subject> subject = new ArrayList<>();
    private List<Schema> schemas = new ArrayList<>();
    private List<TermsOfUse> termsOfUse = new ArrayList<>();
}
