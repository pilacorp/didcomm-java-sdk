package com.pila.credential.common.verificationmethod;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * JWK represents a JSON Web Key structure.
 */
public class JWK {
    @JsonProperty("kty")
    private String kty;

    @JsonProperty("crv")
    private String crv;

    @JsonProperty("x")
    private String x;

    @JsonProperty("y")
    private String y;

    public String getKty() {
        return kty;
    }

    public void setKty(String kty) {
        this.kty = kty;
    }

    public String getCrv() {
        return crv;
    }

    public void setCrv(String crv) {
        this.crv = crv;
    }

    public String getX() {
        return x;
    }

    public void setX(String x) {
        this.x = x;
    }

    public String getY() {
        return y;
    }

    public void setY(String y) {
        this.y = y;
    }
}
