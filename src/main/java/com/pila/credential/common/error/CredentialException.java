package com.pila.credential.common.error;

/**
 * Base for the typed failures callers branch on (Go sentinels such as
 * {@code ErrSDJWTRequiresJOSE}). Plain failures stay {@link Exception}; only the
 * conditions a caller can act on get a {@link Code}.
 */
public class CredentialException extends Exception {

    public enum Code {
        SD_JWT_REQUIRES_JOSE,
        AUDIENCE_UNBOUND,
        ALREADY_SIGNED,
        SCHEMA_VALIDATION,
        REVOKED,
        EXPIRED,
        NOT_VALID_YET,
        INVALID_PROOF,
        UNSUPPORTED_OPTION,
        INVALID_INPUT
    }

    private final Code code;

    public CredentialException(Code code, String message) {
        super(message);
        this.code = code;
    }

    public CredentialException(Code code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public Code getCode() {
        return code;
    }
}
