package com.pila.credential.vccontract;

/** Base for vccontract failures; the nested types replace Go's sentinel errors. */
public class VcContractException extends RuntimeException {
    public VcContractException(String message) {
        super(message);
    }

    public VcContractException(String message, Throwable cause) {
        super(message, cause);
    }

    /** Go ErrNoContractAddress: a view function was called on a client built without a contract address. */
    public static class NoContractAddress extends VcContractException {
        public NoContractAddress(String message) {
            super("no contract address configured: " + message);
        }
    }

    /** Go ErrTxNotFound: no receipt for the tx hash (unknown or not yet mined). */
    public static class TxNotFound extends VcContractException {
        public TxNotFound() {
            super("transaction not found");
        }
    }

    /** Go ErrTxReverted: the tx exists but failed, so it anchored nothing. */
    public static class TxReverted extends VcContractException {
        public TxReverted() {
            super("transaction reverted");
        }
    }

    /** @deprecated only {@link CredentialRegistry#getAnchoredRoot} throws it (Go ErrRootNotAnchored). */
    @Deprecated
    public static class RootNotAnchored extends VcContractException {
        public RootNotAnchored() {
            super("transaction did not anchor a root for this issuer and tree index");
        }
    }

    /** Go ErrUntrustedContract: a per-call pin outside the trusted set. Pins only narrow trust. */
    public static class UntrustedContract extends VcContractException {
        public UntrustedContract(String address) {
            super("contract address is not in this client's trusted set: " + address);
        }
    }
}
