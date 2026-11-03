package com.pila.credential.common.sdjwt;

import java.util.List;

public final class ParsedSDJWT {
    public final String baseJWT;
    public final List<String> disclosures;

    ParsedSDJWT(String baseJWT, List<String> disclosures) {
        this.baseJWT = baseJWT;
        this.disclosures = disclosures;
    }
}
