package com.pila.credential.common.sdjwt;

import java.util.List;

public final class ParsedSDJWT {
    public final String baseJWT;
    public final List<String> disclosures;
    public final List<DecodedDisclosure> decodedDisclosures;

    ParsedSDJWT(String baseJWT, List<String> disclosures, List<DecodedDisclosure> decodedDisclosures) {
        this.baseJWT = baseJWT;
        this.disclosures = disclosures;
        this.decodedDisclosures = decodedDisclosures;
    }
}
