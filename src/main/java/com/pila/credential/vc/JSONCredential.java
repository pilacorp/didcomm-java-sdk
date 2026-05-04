package com.pila.credential.vc;

import com.pila.credential.common.dto.Proof;
import com.pila.credential.common.jsonmap.JSONMap;
import com.pila.credential.common.signer.DefaultSignerProvider;
import com.pila.credential.common.signer.SignerProvider;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Map;

/**
 * JSONCredential represents a verifiable credential in JSON format with
 * embedded proof.
 */
public class JSONCredential implements Credential {
    private CredentialData credentialData;
    private Proof proof;
    private String verificationMethod;

    private static final String DEFAULT_VERIFICATION_METHOD_KEY = "key-1";

    private JSONCredential() {
        this.verificationMethod = DEFAULT_VERIFICATION_METHOD_KEY;
    }

    /**
     * Creates a new JSONCredential from CredentialContents.
     */
    public static JSONCredential newJSONCredential(CredentialContents vcc) throws Exception {
        CredentialData m = CredentialHelper.serializeCredentialContents(vcc);

        JSONCredential e = new JSONCredential();
        e.credentialData = m;

        return e;
    }

    /**
     * Parses a JSONCredential from raw JSON bytes.
     */
    public static JSONCredential parseJSONCredential(byte[] rawJSON) throws Exception {
        if (!CredentialParser.isJSONCredential(rawJSON)) {
            throw new Exception("invalid JSON format");
        }

        if (rawJSON.length == 0) {
            throw new Exception("JSON string is empty");
        }

        CredentialData m = new CredentialData();

        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> map = mapper.readValue(rawJSON, new TypeReference<Map<String, Object>>() {
        });
        m.putAll(map);

        JSONCredential jsonCred = new JSONCredential();
        jsonCred.credentialData = m;

        return jsonCred;
    }

    @Override
    public void addProof(String privKeyHex) throws Exception {
        addProofByProvider(new DefaultSignerProvider(privKeyHex));
    }

    @Override
    public void addProofByProvider(SignerProvider signerProvider) throws Exception {
        Object issuerObj = credentialData.get("issuer");
        if (!(issuerObj instanceof String)) {
            throw new Exception("issuer is missing or invalid");
        }

        String issuer = (String) issuerObj;
        String verificationMethod = issuer + "#" + this.verificationMethod;
        ((JSONMap) credentialData).addECDSAProofByProvider(signerProvider, verificationMethod, "assertionMethod");
    }

    @Override
    public byte[] getSigningInput() throws Exception {
        return ((JSONMap) credentialData).canonicalize();
    }

    @Override
    public void addCustomProof(Proof proof) throws Exception {
        if (proof == null) {
            throw new IllegalArgumentException("proof cannot be null");
        }

        this.proof = proof;
        ((JSONMap) credentialData).addCustomProof(proof);
    }

    @Override
    public void verify() throws Exception {
        // Check if credential has proof
        if (credentialData.get("proof") == null) {
            throw new Exception("credential has no proof");
        }

        String didBaseURL = CredentialConfig.getBaseURL();
        boolean isValid = ((JSONMap) credentialData).verifyProof(didBaseURL);

        if (!isValid) {
            throw new Exception("invalid proof");
        }
    }

    @Override
    public Object serialize() throws Exception {
        // Check if credential has proof
        if (credentialData.get("proof") == null) {
            throw new Exception("credential must have proof before serialization");
        }

        return ((JSONMap) credentialData).toMap();
    }

    @Override
    public byte[] getContents() throws Exception {
        return ((JSONMap) credentialData).toJSON();
    }

    @Override
    public String getType() {
        return "JSON";
    }

    /**
     * Gets the credential data.
     */
    public CredentialData getCredentialData() {
        return credentialData;
    }

    /**
     * Gets the proof.
     */
    public Proof getProof() {
        return proof;
    }

    /**
     * Gets the verification method key.
     */
    public String getVerificationMethod() {
        return verificationMethod;
    }

    /**
     * Sets the verification method key.
     */
    public void setVerificationMethod(String verificationMethod) {
        this.verificationMethod = verificationMethod;
    }
}
