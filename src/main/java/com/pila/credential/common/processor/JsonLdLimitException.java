package com.pila.credential.common.processor;

/** A refusal of this SDK's bounds on JSON-LD loading and canonicalization (go-credential-sdk's Err* values). */
public final class JsonLdLimitException extends Exception {

    public enum Kind {
        /** Every failed remote context fetch (ErrContextLoad); the specific cause is on the chain. */
        LOAD,
        /** Address is not public (ErrContextAddress). */
        ADDRESS,
        /** URL is not http or https (ErrContextScheme). */
        SCHEME,
        /** Too many HTTP requests in one fetch (ErrContextRequests). */
        REQUESTS,
        /** The operation's context budget is used up (ErrContextOverflow). */
        OVERFLOW,
        /** ErrTooManyContextTerms. */
        TOO_MANY_TERMS,
        /** ErrContextTermTooLong. */
        TERM_TOO_LONG,
        /** ErrBlankNodeWork. */
        BLANK_NODE_WORK
    }

    private final Kind kind;

    public JsonLdLimitException(Kind kind, String message) {
        this(kind, message, null);
    }

    public JsonLdLimitException(Kind kind, String message, Throwable cause) {
        super(message, cause);
        this.kind = kind;
    }

    public Kind kind() {
        return kind;
    }

    /** errors.Is: whether {@code t} or anything on its cause chain is a refusal of {@code kind}. */
    public static boolean has(Throwable t, Kind kind) {
        for (int i = 0; t != null && i < 64; i++, t = t.getCause()) {
            if (t instanceof JsonLdLimitException e && e.kind == kind) return true;
        }
        return false;
    }
}
