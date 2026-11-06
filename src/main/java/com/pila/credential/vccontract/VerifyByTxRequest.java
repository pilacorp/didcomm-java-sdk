package com.pila.credential.vccontract;

/**
 * VerifyRequest plus the tx that anchored the root. Derive issuerAddress and leaf from the VC itself, never
 * from the proof bundle: anyone can anchor a tree of their own under their own address, and an inner node
 * folds to the root too.
 */
public class VerifyByTxRequest extends VerifyRequest {
    /** 32-byte hex hash of the anchoring tx; the proof and tx hash must come from the same anchoring. */
    public String txHash;
    /** Optional pin to the deployment that anchored this proof; must already be in the trusted set. */
    public String contractAddress;

    @Override
    public void validate() {
        super.validate();
        try {
            Validation.validateHash32(txHash);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("invalid tx hash: " + e.getMessage());
        }
        if (contractAddress != null && !contractAddress.isEmpty() && !Validation.isHexAddress(contractAddress)) {
            throw new IllegalArgumentException("invalid contract address: \"" + contractAddress + "\"");
        }
    }
}
