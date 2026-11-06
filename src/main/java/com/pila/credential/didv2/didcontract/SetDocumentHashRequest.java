package com.pila.credential.didv2.didcontract;

import com.pila.credential.didv2.Issuer;

/** setDocumentHash(did, docHash, capId, v, r, s) (Go didcontract.SetDocumentHashRequest). */
public final class SetDocumentHashRequest {
    public String didAddress;
    public String docHash;
    public String capId;
    public Issuer.IssuerSignature issuerSig;
    public long nonce;

    public void validate() throws Exception {
        if (!Issuer.isAddress(didAddress)) {
            throw new Exception("invalid did address: " + didAddress);
        }
        RequestChecks.signature(issuerSig);
        RequestChecks.hex32("docHash", docHash);
        RequestChecks.hex32("capID", capId);
    }
}
