package com.pila.credential.vc;

import java.util.HashMap;
import java.util.Map;

/**
 * Subject represents the credentialSubject field.
 */
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

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public Map<String, Object> getCustomFields() {
        return customFields;
    }

    public void setCustomFields(Map<String, Object> customFields) {
        this.customFields = customFields;
    }
}
