package com.pila.credential.vc;

import com.pila.credential.common.signer.TestSignerProvider;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JSONCredentialProviderTest {

    @Test
    void addProofByProvider_writes_proofValue_hex() throws Exception {
        CredentialContents contents = new CredentialContents();
        contents.setIssuer("did:example:issuer");
        contents.setValidFrom(Instant.now());

        JSONCredential credential = JSONCredential.newJSONCredential(contents);

        byte[] sig64 = new byte[64];
        for (int i = 0; i < 64; i++) {
            sig64[i] = (byte) (i + 3);
        }
        credential.addProofByProvider(new TestSignerProvider(sig64));

        Object proofObj = credential.getCredentialData().get("proof");
        assertNotNull(proofObj);
        assertTrue(proofObj instanceof Map);

        @SuppressWarnings("unchecked")
        Map<String, Object> proofMap = (Map<String, Object>) proofObj;

        Object proofValue = proofMap.get("proofValue");
        assertTrue(proofValue instanceof String);
        assertEquals(128, ((String) proofValue).length());
    }
}
