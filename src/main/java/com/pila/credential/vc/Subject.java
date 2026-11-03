package com.pila.credential.vc;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.HashMap;
import java.util.Map;

/**
 * Subject represents the credentialSubject field.
 */
@Getter
@Setter
@NoArgsConstructor
public class Subject {
    private String id;
    private Map<String, Object> customFields = new HashMap<>();

    public Subject(String id, Map<String, Object> customFields) {
        this.id = id;
        this.customFields = customFields != null ? customFields : new HashMap<>();
    }
}
