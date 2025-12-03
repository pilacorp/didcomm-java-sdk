package com.pila.credential.common.verificationmethod;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

/**
 * JWK represents a JSON Web Key structure.
 */
@Data
public class JWK {
    @JsonProperty("kty")
    private String kty; // Key type

    @JsonProperty("crv")
    private String crv; // Curve

    @JsonProperty("x")
    private String x; // X coordinate

    @JsonProperty("y")
    private String y; // Y coordinate
}
