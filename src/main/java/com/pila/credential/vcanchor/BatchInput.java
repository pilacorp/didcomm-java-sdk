package com.pila.credential.vcanchor;

import java.util.List;

public final class BatchInput {
    public final String issuerDid;
    public final String externalTreeId;
    public final List<String> vcHashes;

    public BatchInput(String issuerDid, String externalTreeId, List<String> vcHashes) {
        this.issuerDid = issuerDid;
        this.externalTreeId = externalTreeId;
        this.vcHashes = vcHashes;
    }
}
