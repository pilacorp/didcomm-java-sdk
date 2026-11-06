package com.pila.credential.vc;

/**
 * Consumer-facing credential contract: read, verify and output (Go {@code vc.Credential}). Signing lives on
 * {@link SignableCredential}; selective disclosure on {@link JOSECredential}.
 */
public interface Credential {
    /** Verifies the proof/signature with default options. */
    default void verify() throws Exception {
        verify(null);
    }

    /** Verifies the proof/signature; {@code opts} adds schema, revocation, expiration, resolver, proof-VM. */
    void verify(CredentialOptions opts) throws Exception;

    /**
     * Serializes the credential to its native format.
     *
     * @return a Map (JSON-LD) or the token String (JWT / JOSE)
     */
    Object serialize() throws Exception;

    /** SHA-256 (hex) identity of the full credential including proof/signature. */
    String hash() throws Exception;

    /** The credential contents as JSON bytes. */
    byte[] getContents() throws Exception;

    /** "JSON", "JWT" or "JOSE". */
    String getType();

    /** Field by dot-notation path, or null when absent. */
    Object extractField(String path);
}
