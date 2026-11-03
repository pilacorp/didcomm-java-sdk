package com.pila.credential.vp;

import com.pila.credential.common.verificationmethod.CredentialResolver;

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

    public boolean isVerifyProof() {
        return verifyProof;
    }

    public void setVerifyProof(boolean verifyProof) {
        this.verifyProof = verifyProof;
    }

    public boolean isValidateVC() {
        return validateVC;
    }

    public void setValidateVC(boolean validateVC) {
        this.validateVC = validateVC;
    }

    public boolean isCheckExpiration() {
        return checkExpiration;
    }

    public void setCheckExpiration(boolean checkExpiration) {
        this.checkExpiration = checkExpiration;
    }

    public long getClockSkewLeewayMs() {
        return clockSkewLeewayMs;
    }

    public void setClockSkewLeewayMs(long clockSkewLeewayMs) {
        this.clockSkewLeewayMs = clockSkewLeewayMs;
    }

    public String getVerificationMethodKey() {
        return verificationMethodKey;
    }

    public void setVerificationMethodKey(String verificationMethodKey) {
        this.verificationMethodKey = verificationMethodKey;
    }

    public String getChallenge() {
        return challenge;
    }

    public void setChallenge(String challenge) {
        this.challenge = challenge;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getExpectedChallenge() {
        return expectedChallenge;
    }

    public void setExpectedChallenge(String expectedChallenge) {
        this.expectedChallenge = expectedChallenge;
    }

    public String getExpectedDomain() {
        return expectedDomain;
    }

    public void setExpectedDomain(String expectedDomain) {
        this.expectedDomain = expectedDomain;
    }

    public boolean isRequireAudience() {
        return requireAudience;
    }

    public void setRequireAudience(boolean requireAudience) {
        this.requireAudience = requireAudience;
    }

    public CredentialResolver getResolver() {
        return resolver;
    }

    public void setResolver(CredentialResolver resolver) {
        this.resolver = resolver;
    }
}
