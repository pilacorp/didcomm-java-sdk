package com.pila.credential.vc;

import lombok.Getter;
import lombok.Setter;

/**
 * Schema represents a credential schema with an ID and type.
 */
@Getter
@Setter
public class Schema {
    private String id;
    private String type;
}
