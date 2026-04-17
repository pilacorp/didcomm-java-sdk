package com.pila.credential.vc;

import com.pila.credential.common.verificationmethod.VerificationMethodResolverProvider;

/**
 * Verification options for credentials.
 *
 * <p>
 * Signature verification is always performed. Additional checks such as
 * expiration and credential status are opt-in.
 * </p>
 */
public final class CredentialVerifyOptions {
    private final VerificationMethodResolverProvider verificationMethodResolverProvider;
    private final CredentialStatusProvider credentialStatusProvider;
    private final boolean checkExpiration;
    private final boolean checkStatus;

    private CredentialVerifyOptions(Builder builder) {
        this.verificationMethodResolverProvider = builder.verificationMethodResolverProvider;
        this.credentialStatusProvider = builder.credentialStatusProvider;
        this.checkExpiration = builder.checkExpiration;
        this.checkStatus = builder.checkStatus;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static CredentialVerifyOptions defaults() {
        return builder().build();
    }

    public VerificationMethodResolverProvider getVerificationMethodResolverProvider() {
        return verificationMethodResolverProvider;
    }

    public CredentialStatusProvider getCredentialStatusProvider() {
        return credentialStatusProvider;
    }

    public boolean isCheckExpiration() {
        return checkExpiration;
    }

    public boolean isCheckStatus() {
        return checkStatus;
    }

    public static final class Builder {
        private VerificationMethodResolverProvider verificationMethodResolverProvider;
        private CredentialStatusProvider credentialStatusProvider;
        private boolean checkExpiration;
        private boolean checkStatus;

        private Builder() {
        }

        public Builder verificationMethodResolverProvider(
                VerificationMethodResolverProvider verificationMethodResolverProvider) {
            this.verificationMethodResolverProvider = verificationMethodResolverProvider;
            return this;
        }

        public Builder credentialStatusProvider(CredentialStatusProvider credentialStatusProvider) {
            this.credentialStatusProvider = credentialStatusProvider;
            return this;
        }

        public Builder checkExpiration(boolean checkExpiration) {
            this.checkExpiration = checkExpiration;
            return this;
        }

        public Builder checkStatus(boolean checkStatus) {
            this.checkStatus = checkStatus;
            return this;
        }

        public CredentialVerifyOptions build() {
            return new CredentialVerifyOptions(this);
        }
    }
}
