package com.pila.credential.common.jwt;

import com.pila.credential.common.signer.TestSignerProvider;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class JWTSignerProviderTest {

    @Test
    void signString_normalizes_65_to_64() throws Exception {
        byte[] sig65 = new byte[65];
        for (int i = 0; i < 65; i++) {
            sig65[i] = (byte) i;
        }

        JWTSigner signer = new JWTSigner(new TestSignerProvider(sig65));
        String b64 = signer.signString("header.payload");

        byte[] decoded = Base64.getUrlDecoder().decode(b64);
        assertEquals(64, decoded.length);
        assertArrayEquals(JWTSigner.normalizeJwtSignature(sig65), decoded);
    }
}

