package com.pila.credential.vc;

import com.pila.credential.common.dto.Proof;
import com.pila.credential.common.signer.TestSignerProvider;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class JWTCredentialProviderTest {

    @Test
    void addProofByProvider_creates_64_byte_jwt_signature() throws Exception {
        CredentialContents contents = new CredentialContents();
        contents.setIssuer("did:example:issuer");
        contents.setValidFrom(Instant.now());

        JWTCredential credential = JWTCredential.newJWTCredential(contents);

        byte[] sig65 = new byte[65];
        for (int i = 0; i < 65; i++) {
            sig65[i] = (byte) (i + 1);
        }
        credential.addProofByProvider(new TestSignerProvider(sig65));

        String jwt = (String) credential.serialize();
        String[] parts = jwt.split("\\.");
        assertEquals(3, parts.length);

        byte[] signatureBytes = Base64.getUrlDecoder().decode(parts[2]);
        assertEquals(64, signatureBytes.length);
    }

    @Test
    void addCustomProof_accepts_65_byte_signature_and_normalizes() throws Exception {
        CredentialContents contents = new CredentialContents();
        contents.setIssuer("did:example:issuer");
        contents.setValidFrom(Instant.now());

        JWTCredential credential = JWTCredential.newJWTCredential(contents);

        byte[] sig65 = new byte[65];
        for (int i = 0; i < 65; i++) {
            sig65[i] = (byte) (100 + i);
        }

        Proof proof = new Proof();
        proof.setSignature(sig65);
        credential.addCustomProof(proof);

        String jwt = (String) credential.serialize();
        String[] parts = jwt.split("\\.");
        assertEquals(3, parts.length);

        byte[] signatureBytes = Base64.getUrlDecoder().decode(parts[2]);
        assertEquals(64, signatureBytes.length);
    }
}
