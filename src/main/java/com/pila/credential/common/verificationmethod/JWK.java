package com.pila.credential.common.verificationmethod;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

/**
 * JWK represents a JSON Web Key structure.
 */
@Getter
@Setter
public class JWK {
    @JsonProperty("kty")
    private String kty;

    @JsonProperty("crv")
    private String crv;

    @JsonProperty("x")
    private String x;

    @JsonProperty("y")
    private String y;
}
