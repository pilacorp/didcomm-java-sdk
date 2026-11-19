package com.pila.credential.vc;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** termsOfUse entry as per W3C Verifiable Credentials; {@code type} is required. */
@Getter
@Setter
@NoArgsConstructor
public class TermsOfUse {
    private String id;
    private String type;

    public TermsOfUse(String id, String type) {
        this.id = id;
        this.type = type;
    }
}
