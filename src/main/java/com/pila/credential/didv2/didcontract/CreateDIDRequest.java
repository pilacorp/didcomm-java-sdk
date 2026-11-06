package com.pila.credential.didv2.didcontract;

import com.pila.credential.didv2.Issuer;

/** Everything needed to build the createDID transaction (Go didcontract.CreateDIDRequest). */
public final class CreateDIDRequest {
    public String issuerAddress;
    public Issuer.IssuerSignature issuerSig;
    public String docHash;
    public String capId;
    public int didType;
    public long nonce;

    /** Go CreateDIDRequest.Validate. */
    public void validate() throws Exception {
        if (!Issuer.isAddress(issuerAddress)) {
            throw new Exception("invalid issuer address: " + issuerAddress);
        }
        RequestChecks.signature(issuerSig);
        RequestChecks.hex32("docHash", docHash);
        RequestChecks.hex32("capID", capId);
        if (didType < 0 || didType > 0xff) {
            throw new Exception("invalid did type: " + didType);
        }
    }
}
