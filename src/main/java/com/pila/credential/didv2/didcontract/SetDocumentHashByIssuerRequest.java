package com.pila.credential.didv2.didcontract;

import com.pila.credential.didv2.Issuer;

/** setDocumentHashByIssuer(did, docHash) (Go didcontract.SetDocumentHashByIssuerRequest). */
public final class SetDocumentHashByIssuerRequest {
    public String didAddress;
    public String docHash;
    public long nonce;

    public void validate() throws Exception {
        if (!Issuer.isAddress(didAddress)) {
            throw new Exception("invalid did address: " + didAddress);
        }
        RequestChecks.hex32("docHash", docHash);
    }
}
