package com.pila.credential.didv2.did;

import static org.junit.jupiter.api.Assertions.*;

import com.pila.credential.common.verificationmethod.DIDDocument;
import com.pila.credential.common.verificationmethod.VerificationMethodEntry;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/** Go #184: SoftReasonCanBecomeKeyCompromise, SecondRevokeOtherwiseRefused, ErrAlreadyRevoked on rotate. */
class RevokeAgainTest {
    static DIDDocument doc() {
        DIDDocument d = new DIDDocument();
        d.setId("did:example:a");
        d.setContext(new ArrayList<>(List.of("https://www.w3.org/ns/did/v1", "https://w3id.org/security/v1")));
        VerificationMethodEntry vm = new VerificationMethodEntry();
        vm.setId("did:example:a#key-1");
        d.setVerificationMethod(new ArrayList<>(List.of(vm)));
        return d;
    }

    @Test
    void softReasonCanBecomeKeyCompromise() throws Exception {
        DIDDocument d = doc();
        Instant t = Instant.parse("2024-01-01T00:00:00Z");
        DIDDocumentOps.revokeVerificationMethod(d, "did:example:a#key-1", "superseded", t);
        String first = d.getVerificationMethod().get(0).getRevoked();
        DIDDocumentOps.revokeVerificationMethod(d, "did:example:a#key-1", "keyCompromise", Instant.parse("2025-01-01T00:00:00Z"));
        VerificationMethodEntry vm = d.getVerificationMethod().get(0);
        assertEquals("keyCompromise", vm.getRevocationReason());
        assertEquals(first, vm.getRevoked()); // the first revoked time stays
        assertTrue(d.getContext().contains(DIDDocumentOps.CID_CONTEXT)); // ensureContext runs on this path too
    }

    @Test
    void anyOtherSecondRevokeIsRefusedWithAlreadyRevoked() throws Exception {
        DIDDocument d = doc();
        DIDDocumentOps.revokeVerificationMethod(d, "did:example:a#key-1", "keyCompromise", Instant.now());
        assertThrows(DIDDocumentOps.AlreadyRevokedException.class,
                () -> DIDDocumentOps.revokeVerificationMethod(d, "did:example:a#key-1", "superseded", Instant.now()));
        assertThrows(DIDDocumentOps.AlreadyRevokedException.class,
                () -> DIDDocumentOps.revokeVerificationMethod(d, "did:example:a#key-1", "keyCompromise", Instant.now()));
        VerificationMethodEntry n = new VerificationMethodEntry();
        assertThrows(DIDDocumentOps.AlreadyRevokedException.class,
                () -> DIDDocumentOps.rotateVerificationMethod(d, "did:example:a#key-1", n, "superseded", Instant.now()));
    }
}
