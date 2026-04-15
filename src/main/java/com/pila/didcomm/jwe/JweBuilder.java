package com.pila.didcomm.jwe;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

public final class JweBuilder {
    private JweBuilder() {}

    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);

    public static String base64url(byte[] input) {
        return URL_ENCODER.encodeToString(input);
    }

    public static String build(byte[] iv, byte[] ciphertext, byte[] tag) {
        try {
            Map<String, Object> header = new LinkedHashMap<>();
            header.put("alg", "ECDH-ES");
            header.put("enc", "A256GCM");
            header.put("crv", "secp256k1");
            header.put("typ", "application/didcomm-encrypted+json");
            byte[] headerBytes = MAPPER.writeValueAsBytes(header);

            Map<String, Object> jwe = new LinkedHashMap<>();
            jwe.put("protected", base64url(headerBytes));
            jwe.put("iv", base64url(iv));
            jwe.put("ciphertext", base64url(ciphertext));
            jwe.put("tag", base64url(tag));

            return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(jwe);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}


