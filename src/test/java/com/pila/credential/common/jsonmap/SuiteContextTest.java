package com.pila.credential.common.jsonmap;

import com.pila.credential.common.signer.DefaultSignerProvider;
import com.pila.credential.common.signer.P256SignerProvider;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** 2.13 / 2.14: how signing amends @context, as go-credential-sdk's jsonmap does. */
class SuiteContextTest {

    private static final String PRIV = "2c79686425aee8002cb189bf294f2d52ca43851797c7b6e78a7dc361c4373e46";
    private static final String VM = "did:example:i#key-1";

    @Test
    void rdfcSigningWrapsAnInlineObjectContext() throws Exception {
        Map<String, Object> inline = new LinkedHashMap<>();
        inline.put("@vocab", "https://example.org/vocab#");
        JSONMap m = new JSONMap();
        m.put("@context", inline);
        m.put("id", "urn:uuid:1");
        m.put("name", "Alice");
        m.addECDSAProofByProvider(new P256SignerProvider(PRIV), VM, "assertionMethod");
        assertEquals(List.of(inline, "https://w3id.org/security/data-integrity/v2"), m.get("@context"));
        assertNotNull(m.get("proof"));
    }

    @Test
    void secp256k1SigningNeedsAContext() {
        JSONMap m = new JSONMap();
        m.put("id", "urn:uuid:1");
        // Go fails here too, canonicalizing the document before it adds the suite context.
        assertThrows(Exception.class,
                () -> m.addEcdsaSecp256k1ProofByProvider(new DefaultSignerProvider(PRIV), VM, "assertionMethod", null, null));
        assertEquals(null, m.get("proof"));
        assertEquals(null, m.get("@context"));
    }

    @Test
    void credentialsV1JsonldSpellingAlreadyDefinesTheSuite() throws Exception {
        JSONMap m = new JSONMap();
        m.put("@context", List.of("https://www.w3.org/2018/credentials/v1.jsonld"));
        m.put("type", List.of("VerifiableCredential"));
        m.put("issuer", "did:example:i");
        m.put("issuanceDate", "2026-01-01T00:00:00Z");
        m.put("credentialSubject", Map.of("id", "did:example:s"));
        m.addEcdsaSecp256k1ProofByProvider(new DefaultSignerProvider(PRIV), VM, "assertionMethod", null, null);
        assertEquals(List.of("https://www.w3.org/2018/credentials/v1.jsonld"), m.get("@context"));
    }
}
