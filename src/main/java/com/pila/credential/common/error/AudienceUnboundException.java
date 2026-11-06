package com.pila.credential.common.error;

/** {@code withRequireAudience} without {@code withExpectedDomain} (Go {@code ErrAudienceUnbound}). */
public class AudienceUnboundException extends CredentialException {
    public AudienceUnboundException() {
        super(Code.AUDIENCE_UNBOUND, "WithRequireAudience needs WithExpectedDomain");
    }
}
