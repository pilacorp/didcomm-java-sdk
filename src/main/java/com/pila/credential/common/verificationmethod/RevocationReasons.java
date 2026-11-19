package com.pila.credential.common.verificationmethod;

/**
 * Revocation reason taxonomy aligned with go-credential-sdk.
 */
public final class RevocationReasons {
    public static final String KEY_COMPROMISE = "keyCompromise";
    /** RotateVerificationMethod's default reason (Go ReasonSuperseded). */
    public static final String SUPERSEDED = "superseded";

    private RevocationReasons() {
    }

    public static boolean isHardRevocationReason(String reason) {
        return KEY_COMPROMISE.equals(reason);
    }
}
