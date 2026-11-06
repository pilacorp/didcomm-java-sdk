package com.pila.credential.vp;

import com.pila.credential.common.verificationmethod.CredentialResolver;
import com.pila.credential.vc.CredentialOptions;
import lombok.Getter;
import lombok.Setter;

import java.time.Duration;

/**
 * Go {@code PresentationOpt} equivalents: challenge/domain, audience, resolver, VC validation. Every option is read
 * by the call it is documented for; one a call site cannot honour is refused, not silently ignored.
 */
@Getter
@Setter
public class PresentationOptions {
    private boolean verifyProof;
    private boolean validateVC;
    /** Options forwarded to each embedded credential's verify when {@code withVCValidation} is on. */
    private CredentialOptions vcOptions;
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

    /** Verifies every embedded credential (with the resolver and leeway of this call). */
    public PresentationOptions withVCValidation() {
        this.validateVC = true;
        return this;
    }

    /** As {@link #withVCValidation()}, with extra options for each embedded credential. */
    public PresentationOptions withVCValidation(CredentialOptions vcOpts) {
        this.validateVC = true;
        this.vcOptions = vcOpts;
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

    public PresentationOptions withLeeway(Duration d) {
        return withLeewayMs(d.toMillis());
    }

    public PresentationOptions withVerificationMethodKey(String key) {
        if (key != null && !key.isEmpty()) {
            this.verificationMethodKey = key;
        }
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

    // The expected-value and audience checks are only meaningful against a signature-verified proof, so each of
    // these enables proof verification (Go parity).
    public PresentationOptions withExpectedChallenge(String challenge) {
        this.expectedChallenge = challenge;
        this.verifyProof = true;
        return this;
    }

    public PresentationOptions withExpectedDomain(String domain) {
        this.expectedDomain = domain;
        this.verifyProof = true;
        return this;
    }

    public PresentationOptions withRequireAudience() {
        this.requireAudience = true;
        this.verifyProof = true;
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

    /** JWT/JOSE signing may replace an existing signature; JSON-LD signing refuses this option. */
    public PresentationOptions withReplaceProof() {
        this.replaceProof = true;
        return this;
    }

    public PresentationOptions withBaseURL(String baseURL) {
        this.didBaseURL = baseURL;
        return this;
    }

    /** Resolver for this call: injected, else HTTP at {@code withBaseURL}, else the package default. */
    public CredentialResolver effectiveResolver() {
        if (resolver != null) {
            return resolver;
        }
        if (didBaseURL != null && !didBaseURL.isEmpty()) {
            return com.pila.credential.vc.CredentialConfig.resolverFor(didBaseURL);
        }
        return PresentationConfig.defaultResolver();
    }

    public PresentationOptions copy() {
        PresentationOptions c = new PresentationOptions();
        c.verifyProof = verifyProof;
        c.validateVC = validateVC;
        c.vcOptions = vcOptions;
        c.checkExpiration = checkExpiration;
        c.clockSkewLeewayMs = clockSkewLeewayMs;
        c.verificationMethodKey = verificationMethodKey;
        c.challenge = challenge;
        c.domain = domain;
        c.expectedChallenge = expectedChallenge;
        c.expectedDomain = expectedDomain;
        c.requireAudience = requireAudience;
        c.resolver = resolver;
        c.proofVerificationMethod = proofVerificationMethod;
        c.replaceProof = replaceProof;
        c.didBaseURL = didBaseURL;
        return c;
    }

    /** Copy with proof verification off: there is no signature to verify before signing. */
    public PresentationOptions forSigning() {
        PresentationOptions c = copy();
        c.verifyProof = false;
        return c;
    }

    static PresentationOptions orEmpty(PresentationOptions o) {
        return o != null ? o : new PresentationOptions();
    }
}
