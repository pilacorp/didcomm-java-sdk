package com.pila.credential.vc;

import com.pila.credential.common.dto.Proof;
import com.pila.credential.common.signer.SignerProvider;

/** A credential this SDK can sign or take an external signature for. */
public interface SignableCredential extends Credential {
    /** Signs with a raw private key (hex); curve is type-specific, see each implementation. */
    default void addProof(String privKeyHex) throws Exception {
        addProof(privKeyHex, null);
    }

    void addProof(String privKeyHex, CredentialOptions opts) throws Exception;

    default void addProofByProvider(SignerProvider signerProvider) throws Exception {
        addProofByProvider(signerProvider, null);
    }

    void addProofByProvider(SignerProvider signerProvider, CredentialOptions opts) throws Exception;

    /** Bytes (JWS) or digest (JSON-LD) an external signer must sign. */
    byte[] getSigningInput() throws Exception;

    default void addCustomProof(Proof proof) throws Exception {
        addCustomProof(proof, null);
    }

    void addCustomProof(Proof proof, CredentialOptions opts) throws Exception;
}
