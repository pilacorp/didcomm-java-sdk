package com.pila.credential.digitalcredential.didresolver;

import static org.junit.jupiter.api.Assertions.*;

import com.pila.credential.digitalcredential.didresolver.DidResolver.*;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

class DidResolverTest {
    static final String DID = "did:example:abc";
    // P-256 Multikey from the W3C CID spec examples.
    static final String MB = "zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169";

    static DidResolver resolver(String json) {
        return new DidResolver(d -> json.getBytes(StandardCharsets.UTF_8), null);
    }

    static String doc(String vmExtra) {
        return "{\"id\":\"" + DID + "\",\"verificationMethod\":[{\"id\":\"" + DID + "#k1\",\"controller\":\"" + DID
                + "\",\"type\":\"Multikey\",\"publicKeyMultibase\":\"" + MB + "\"" + vmExtra + "}],"
                + "\"assertionMethod\":[\"#k1\"]}";
    }

    @Test
    void readsAssertionKey() throws Exception {
        List<IssuerKey> keys = resolver(doc("")).keys(DID);
        assertEquals(1, keys.size());
        assertEquals(DID + "#k1", keys.get(0).kid());
    }

    @Test
    void revokedKeyCompromiseOrNoReasonIsDropped_softReasonKept() throws Exception {
        String rev = ",\"revoked\":\"2020-01-01T00:00:00Z\"";
        assertTrue(resolver(doc(rev)).keys(DID).isEmpty());
        assertTrue(resolver(doc(rev + ",\"revocationReason\":\"keyCompromise\"")).keys(DID).isEmpty());
        assertEquals(1, resolver(doc(rev + ",\"revocationReason\":\"superseded\"")).keys(DID).size());
        assertTrue(resolver(doc(",\"expires\":\"2020-01-01T00:00:00Z\"")).keys(DID).isEmpty());
        assertTrue(resolver(doc(",\"revoked\":\"garbage\"")).keys(DID).isEmpty());
    }

    @Test
    void refusesWhatGoRefuses() {
        assertThrows(IssuerNotSupportedException.class, () -> resolver(doc("")).keys("https://x.example"));
        assertThrows(IssuerNotSupportedException.class, () -> resolver(doc("")).keys("did:example:a/b"));
        assertThrows(NoUsableKeyException.class, () -> resolver(doc("").replace(DID + "\",\"v", "did:other:x\",\"v")).keys(DID));
        assertThrows(NoUsableKeyException.class, () -> resolver("{\"didDocumentMetadata\":{\"deactivated\":true}}").keys(DID));
        assertThrows(IssuerNotSupportedException.class, () -> resolver(
                "{\"didResolutionMetadata\":{\"error\":{\"type\":\"https://www.w3.org/ns/did#METHOD_NOT_SUPPORTED\"}}}").keys(DID));
        // a method of another controller does not belong to this document
        assertThrows(Exception.class, () -> { // duplicate keys in the JSON are refused
            resolver("{\"id\":\"" + DID + "\",\"id\":\"x\"}").keys(DID);
        });
    }

    @Test
    void foreignControllerSkipped() throws Exception {
        String d = doc("").replace("\"controller\":\"" + DID + "\"", "\"controller\":\"did:other:z\"");
        assertTrue(resolver(d).keys(DID, Instant.now()).isEmpty());
    }
}
