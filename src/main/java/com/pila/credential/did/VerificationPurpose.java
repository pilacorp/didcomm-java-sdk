package com.pila.credential.did;

public enum VerificationPurpose {
    AUTHENTICATION("authentication"),
    ASSERTION_METHOD("assertionMethod");

    private final String value;

    VerificationPurpose(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }

    public static VerificationPurpose from(String s) {
        if (AUTHENTICATION.value.equals(s)) {
            return AUTHENTICATION;
        }
        if (ASSERTION_METHOD.value.equals(s)) {
            return ASSERTION_METHOD;
        }
        throw new IllegalArgumentException("unsupported purpose: " + s);
    }
}
