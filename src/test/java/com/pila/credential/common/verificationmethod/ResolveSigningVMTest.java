package com.pila.credential.common.verificationmethod;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ResolveSigningVMTest {
    private static final String DID = "did:pila:abc123";

    private static DIDDocument baseDoc() {
        DIDDocument doc = new DIDDocument();
        doc.setId(DID);
        doc.setContext(new ArrayList<>(List.of()));
        VerificationMethodEntry k1 = vm(DID + "#key-1");
        k1.setRevoked("2026-01-01T00:00:00Z");
        VerificationMethodEntry k2 = vm(DID + "#key-2");
        doc.setVerificationMethod(new ArrayList<>(List.of(k1, k2)));
        doc.setAuthentication(new ArrayList<>(List.of(DID + "#key-1", DID + "#key-2")));
        doc.setAssertionMethod(new ArrayList<>(List.of(DID + "#key-1", DID + "#key-2")));
        return doc;
    }

    private static VerificationMethodEntry vm(String id) {
        VerificationMethodEntry e = new VerificationMethodEntry();
        e.setId(id);
        e.setType("EcdsaSecp256k1VerificationKey2019");
        e.setController(DID);
        return e;
    }

    private static DocumentResolver stub(DIDDocument doc) {
        return did -> doc;
    }

    @Test
    void rejectsPinnedRevokedKid() {
        Exception ex = assertThrows(Exception.class,
                () -> ResolveVmUrl.resolveSigningVM(DID, "assertionMethod", "key-1", stub(baseDoc())));
        assertTrue(ex.getMessage().contains("was revoked at 2026-01-01T00:00:00Z"));
    }

    @Test
    void rejectsHardRevocationReasonWithoutTimestamp() {
        DIDDocument hard = new DIDDocument();
        hard.setId(DID);
        VerificationMethodEntry k1 = vm(DID + "#key-1");
        k1.setRevocationReason("keyCompromise");
        hard.setVerificationMethod(new ArrayList<>(List.of(k1)));
        hard.setAssertionMethod(new ArrayList<>(List.of(DID + "#key-1")));
        Exception ex = assertThrows(Exception.class,
                () -> ResolveVmUrl.resolveSigningVM(DID, "assertionMethod", "key-1", stub(hard)));
        assertTrue(ex.getMessage().contains("hard reason 'keyCompromise'"));
    }

    @Test
    void acceptsPinnedActiveKid() throws Exception {
        var got = ResolveVmUrl.resolveSigningVM(DID, "assertionMethod", "key-2", stub(baseDoc()));
        assertEquals(DID + "#key-2", got.url());
    }

    @Test
    void rejectsKidNotGrantedPurpose() {
        DIDDocument narrowed = baseDoc();
        narrowed.getVerificationMethod().get(0).setRevoked(null);
        narrowed.setAssertionMethod(new ArrayList<>(List.of(DID + "#key-2")));
        Exception ex = assertThrows(Exception.class,
                () -> ResolveVmUrl.resolveSigningVM(DID, "assertionMethod", "key-1", stub(narrowed)));
        assertTrue(ex.getMessage().contains("not granted purpose 'assertionMethod'"));
    }

    @Test
    void normalizeKidForms() {
        assertEquals("", ResolveVmUrl.normalizeVerificationMethodURL(DID, ""));
        assertEquals(DID + "#key-1", ResolveVmUrl.normalizeVerificationMethodURL(DID, DID + "#key-1"));
        assertEquals(DID + "#key-1", ResolveVmUrl.normalizeVerificationMethodURL(DID, "#key-1"));
        assertEquals(DID + "#key-2", ResolveVmUrl.normalizeVerificationMethodURL(DID, "key-2"));
    }
}
