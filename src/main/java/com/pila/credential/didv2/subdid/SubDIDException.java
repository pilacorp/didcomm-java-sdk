package com.pila.credential.didv2.subdid;

/** Sub-DID verification could not reach a verdict (Go ErrNotAnchored, ErrDocumentRequired, ErrChainUnavailable, ErrChainMismatch). */
public final class SubDIDException extends Exception {
    public enum Kind {
        /** Comes from the proof alone; no chain is read. */
        NOT_ANCHORED,
        DOCUMENT_REQUIRED,
        CHAIN_UNAVAILABLE,
        /** The node reports another chain id; also CHAIN_UNAVAILABLE. */
        CHAIN_MISMATCH,
        INVALID_REQUEST
    }

    private final Kind kind;

    public SubDIDException(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }

    public SubDIDException(Kind kind, String message, Throwable cause) {
        super(message, cause);
        this.kind = kind;
    }

    public Kind kind() {
        return kind;
    }

    /** Go {@code errors.Is(err, ErrChainUnavailable)}: a chain mismatch is an unavailable chain too. */
    public boolean isChainUnavailable() {
        return kind == Kind.CHAIN_UNAVAILABLE || kind == Kind.CHAIN_MISMATCH;
    }

    public boolean isChainMismatch() {
        return kind == Kind.CHAIN_MISMATCH;
    }
}
