package com.pila.credential.vc;

import com.pila.credential.common.dto.Proof;

/**
 * Credential interface for verifiable credentials.
 */
public interface Credential {
    /**
     * Adds a proof to the credential using a private key.
     * 
     * @param privKeyHex The private key in hex format
     * @throws Exception if proof addition fails
     */
    void addProof(String privKeyHex) throws Exception;

    /**
     * Gets the signing input (canonicalized data) for the credential.
     * 
     * @return The signing input bytes
     * @throws Exception if getting signing input fails
     */
    byte[] getSigningInput() throws Exception;

    /**
     * Adds a custom proof to the credential.
     * 
     * @param proof The proof object to add
     * @throws Exception if proof addition fails
     */
    void addCustomProof(Proof proof) throws Exception;

    /**
     * Verifies the credential proof.
     * 
     * @throws Exception if verification fails
     */
    default void verify() throws Exception {
        verify(CredentialVerifyOptions.defaults());
    }

    /**
     * Verifies the credential proof using the supplied options.
     *
     * @param options verification options
     * @throws Exception if verification fails
     */
    void verify(CredentialVerifyOptions options) throws Exception;

    /**
     * Serializes the credential to its native format.
     * 
     * @return The serialized credential (Map for JSON, String for JWT)
     * @throws Exception if serialization fails
     */
    Object serialize() throws Exception;

    /**
     * Gets the credential contents as JSON bytes.
     * 
     * @return The credential contents as JSON bytes
     * @throws Exception if getting contents fails
     */
    byte[] getContents() throws Exception;

    /**
     * Gets the credential type.
     * 
     * @return The credential type ("JSON" or "JWT")
     */
    String getType();
}
