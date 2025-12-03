package com.pila.credential.vc;

import com.pila.credential.common.jsonmap.JSONMap;

import java.util.Map;

/**
 * CredentialData represents credential data in JSON format (suitable for both
 * JWT and JSON credentials).
 * This is a type alias equivalent to JSONMap.
 */
public class CredentialData extends JSONMap {

    public CredentialData() {
        super();
    }

    public CredentialData(Map<? extends String, ?> m) {
        super(m);
    }
}
