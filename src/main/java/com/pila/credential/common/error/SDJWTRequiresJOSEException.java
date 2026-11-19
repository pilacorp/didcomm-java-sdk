package com.pila.credential.common.error;

/**
 * Selective disclosure was asked of the VC 1.1 JWT path (Go {@code ErrSDJWTRequiresJOSE}).
 * Use {@code JOSECredential} (vc+sd-jwt) instead.
 */
public class SDJWTRequiresJOSEException extends CredentialException {
    public SDJWTRequiresJOSEException(String context) {
        super(Code.SD_JWT_REQUIRES_JOSE, context
                + ": selective disclosure is supported only as vc+sd-jwt; use JOSECredential.create / JOSECredential.parse");
    }
}
