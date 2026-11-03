package com.pila.credential.vp;

import com.pila.credential.common.verificationmethod.CredentialResolver;
import lombok.Getter;
import lombok.Setter;

/**
 * Go {@code PresentationOpt} equivalents: challenge/domain, audience, resolver, VC validation.
 */
@Getter
@Setter
public class PresentationOptions {
    private boolean verifyProof;
    private boolean validateVC;
    private boolean checkExpiration;
    private long clockSkewLeewayMs;
    private String verificationMethodKey;
    private String challenge;
    private String domain;
    private String expectedChallenge;
    private String expectedDomain;
    private boolean requireAudience;
    private CredentialResolver resolver;
    private String proofVerificationMethod;
    private boolean replaceProof;
    private String didBaseURL;

    public PresentationOptions withVerifyProof() {
        this.verifyProof = true;
        return this;
    }

    public PresentationOptions withVCValidation() {
        this.validateVC = true;
        return this;
    }

    public PresentationOptions withCheckExpiration() {
        this.checkExpiration = true;
        return this;
    }

    public PresentationOptions withLeewayMs(long ms) {
        this.clockSkewLeewayMs = Math.max(ms, 0);
        return this;
    }

    public PresentationOptions withVerificationMethodKey(String key) {
        this.verificationMethodKey = key;
        return this;
    }

    public PresentationOptions withChallenge(String challenge) {
        this.challenge = challenge;
        return this;
    }

    public PresentationOptions withDomain(String domain) {
        this.domain = domain;
        return this;
    }

    public PresentationOptions withExpectedChallenge(String challenge) {
        this.expectedChallenge = challenge;
        return this;
    }

    public PresentationOptions withExpectedDomain(String domain) {
        this.expectedDomain = domain;
        return this;
    }

    public PresentationOptions withRequireAudience() {
        this.requireAudience = true;
        return this;
    }

    public PresentationOptions withResolver(CredentialResolver resolver) {
        this.resolver = resolver;
        return this;
    }

    public PresentationOptions withProofVerificationMethod(String vm) {
        this.proofVerificationMethod = vm;
        return this;
    }

    public PresentationOptions withReplaceProof() {
        this.replaceProof = true;
        return this;
    }

    public PresentationOptions withBaseURL(String baseURL) {
        this.didBaseURL = baseURL;
        return this;
    }
}
