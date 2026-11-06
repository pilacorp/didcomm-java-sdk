package com.pila.credential.common.verificationmethod;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * JWK represents a JSON Web Key structure: EC (kty/crv/x/y), RSA (kty/n/e) and any
 * other member, which is kept in {@link #getAdditional()} so a published JWK map
 * round-trips (DIDv2 document hash covers the whole map).
 */
@Getter
@Setter
@JsonInclude(JsonInclude.Include.NON_NULL)
public class JWK {
    @JsonProperty("kty")
    private String kty;

    @JsonProperty("crv")
    private String crv;

    @JsonProperty("x")
    private String x;

    @JsonProperty("y")
    private String y;

    /** RSA modulus (base64url). */
    @JsonProperty("n")
    private String n;

    /** RSA public exponent (base64url). */
    @JsonProperty("e")
    private String e;

    private final Map<String, Object> additional = new LinkedHashMap<>();

    @JsonAnySetter
    public void putAdditional(String name, Object value) {
        additional.put(name, value);
    }

    @JsonAnyGetter
    public Map<String, Object> getAdditional() {
        return additional;
    }

    /** True when the JWK carries no member at all (Go: an empty publicKeyJwk map). */
    @JsonIgnore
    public boolean isEmpty() {
        return kty == null && crv == null && x == null && y == null && n == null && e == null && additional.isEmpty();
    }

    /** All members present, as a map (Go {@code map[string]any}). */
    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        if (kty != null) m.put("kty", kty);
        if (crv != null) m.put("crv", crv);
        if (x != null) m.put("x", x);
        if (y != null) m.put("y", y);
        if (n != null) m.put("n", n);
        if (e != null) m.put("e", e);
        m.putAll(additional);
        return m;
    }
}
