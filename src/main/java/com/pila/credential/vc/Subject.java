package com.pila.credential.vc;

import lombok.Data;

import java.util.HashMap;
import java.util.Map;

/**
 * Subject represents the credentialSubject field.
 */
@Data
public class Subject {
    private String id;
    private Map<String, Object> customFields;

    public Subject() {
        this.customFields = new HashMap<>();
    }

    public Subject(String id, Map<String, Object> customFields) {
        this.id = id;
        this.customFields = customFields != null ? customFields : new HashMap<>();
    }
}
