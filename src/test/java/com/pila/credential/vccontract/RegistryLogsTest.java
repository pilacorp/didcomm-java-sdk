package com.pila.credential.vccontract;

import static com.pila.credential.vccontract.Fx.*;
import static org.junit.jupiter.api.Assertions.*;

import com.pila.credential.vccontract.ReceiptSource.Log;
import com.pila.credential.vccontract.ReceiptSource.TxReceipt;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

@SuppressWarnings("deprecation")
class RegistryLogsTest {
    static final String TX = leaf(0xcd);
    static final String WANT = leaf(0xbb);

    static boolean anchored(CredentialRegistry r, String root) {
        return r.isRootAnchored(TX, ISSUER, root);
    }

    @Test
    void readsEveryEventShape() {
        for (Shape s : everyShape(REGISTRY, ISSUER, WANT)) {
            assertTrue(anchored(registry(stub(ok(s.log()))), WANT), s.name());
        }
    }

    @Test
    void rejectsARootNotInTheLogs() {
        for (Shape s : everyShape(REGISTRY, ISSUER, WANT)) {
            assertFalse(anchored(registry(stub(ok(s.log()))), leaf(0xcc)), s.name());
        }
    }

    @Test
    void rejectsAnotherIssuersRoot() {
        for (Shape s : everyShape(REGISTRY, OTHER, WANT)) {
            assertFalse(anchored(registry(stub(ok(s.log()))), WANT), s.name());
        }
    }

    @Test
    void rejectsForeignEmitter() {
        for (Shape s : everyShape(ATTACKER, ISSUER, WANT)) {
            assertFalse(anchored(registry(stub(ok(s.log()))), WANT), s.name());
        }
    }

    @Test
    void emitterAddressCaseDoesNotMatter() {
        Log l = singleLog(REGISTRY.toUpperCase().replace("0X", "0x"), ISSUER, WANT);
        assertTrue(anchored(registry(stub(ok(l))), WANT));
    }

    @Test
    void trustsEveryConfiguredContract() {
        CredentialRegistry r = registry(stub(ok(legacyBatchLog(LEGACY, List.of(ISSUER), List.of(WANT)))), LEGACY);
        assertTrue(anchored(r, WANT));
    }

    @Test
    void readsMixedLogsInOneReceipt() {
        CredentialRegistry r = registry(stub(ok(
                legacyBatchLog(LEGACY, List.of(OTHER), List.of(leaf(1))),
                batchLog(REGISTRY, List.of(ISSUER), List.of(WANT)))), LEGACY);
        assertTrue(anchored(r, WANT));
    }

    @Test
    void pinsEmitter() {
        CredentialRegistry r = registry(stub(ok(legacyBatchLog(LEGACY, List.of(ISSUER), List.of(WANT)))), LEGACY);
        assertTrue(r.isRootAnchoredAtContract(TX, ISSUER, WANT, LEGACY));
        assertFalse(r.isRootAnchoredAtContract(TX, ISSUER, WANT, REGISTRY));
    }

    @Test
    void rejectsUntrustedPin() {
        CredentialRegistry r = registry(stub(ok(batchLog(REGISTRY, List.of(ISSUER), List.of(WANT)))));
        assertThrows(VcContractException.UntrustedContract.class,
                () -> r.isRootAnchoredAtContract(TX, ISSUER, WANT, ATTACKER));
    }

    @Test
    void topiclessAndTruncatedLogs() {
        assertFalse(anchored(registry(stub(ok(new Log(REGISTRY, List.of(), "0x")))), WANT));
        for (String ev : List.of("TreeRootAnchored", "IssuerRootsAnchored", "TreeUpdated")) {
            Log l = new Log(REGISTRY, List.of(topic(ev)), "0x");
            assertFalse(anchored(registry(stub(ok(l))), WANT), ev);
        }
        // a topic that is not 32 bytes cannot be indexed into
        Log shortTopic = new Log(REGISTRY, List.of(topic("TreeRootAnchored"), "0x1234", WANT), "0x");
        assertFalse(anchored(registry(stub(ok(shortTopic))), WANT));
    }

    @Test
    void receiptOutcomes() {
        assertThrows(VcContractException.TxNotFound.class,
                () -> anchored(registry(failing(new VcContractException.TxNotFound())), WANT));
        assertThrows(VcContractException.TxReverted.class,
                () -> anchored(registry(stub(new TxReceipt(0, List.of()))), WANT));
        // a source that returns nothing is an error, not "not found" and not false
        VcContractException e = assertThrows(VcContractException.class, () -> anchored(registry(stub(null)), WANT));
        assertFalse(e instanceof VcContractException.TxNotFound);
        // other source failures propagate untouched
        assertThrows(IllegalStateException.class, () -> anchored(registry(failing(new IllegalStateException("rpc"))), WANT));
    }

    @Test
    void withoutAReceiptSource() {
        assertThrows(IllegalStateException.class, () -> anchored(new CredentialRegistry(null, null, ""), WANT));
    }

    @Test
    void rejectsABatchLogWithMismatchedArrays() {
        Log current = new Log(REGISTRY, List.of(topic("BatchRootsAnchored")),
                encode(words(List.of(ISSUER, OTHER)), List.of(WANT)));
        Log legacy = new Log(REGISTRY, List.of(topic("BatchTreesUpdated")), encode(words(List.of(ISSUER, OTHER)),
                List.of(java.math.BigInteger.valueOf(7)), List.of(WANT)));
        assertFalse(anchored(registry(stub(ok(current))), WANT));
        assertFalse(anchored(registry(stub(ok(legacy))), WANT));
        // malformed ABI data also fails closed
        assertFalse(anchored(registry(stub(ok(new Log(REGISTRY, List.of(topic("BatchRootsAnchored")), "0x1234")))), WANT));
    }

    @Test
    void getAnchoredRootStillServesLegacyAnchorings() {
        CredentialRegistry r = registry(stub(ok(
                legacyBatchLog(REGISTRY, List.of(OTHER, ISSUER), List.of(leaf(1), WANT)))));
        assertEquals(WANT, r.getAnchoredRoot(TX, ISSUER, LEGACY_TREE_INDEX + 1));
        assertThrows(VcContractException.RootNotAnchored.class, () -> r.getAnchoredRoot(TX, ISSUER, 99));
    }

    @Test
    void getAnchoredRootFindsNothingInCurrentEvents() {
        for (Log l : List.of(singleLog(REGISTRY, ISSUER, WANT), batchLog(REGISTRY, List.of(ISSUER), List.of(WANT)),
                issuerBatchLog(REGISTRY, ISSUER, List.of(WANT)))) {
            assertThrows(VcContractException.RootNotAnchored.class,
                    () -> registry(stub(ok(l))).getAnchoredRoot(TX, ISSUER, LEGACY_TREE_INDEX));
        }
        assertThrows(VcContractException.TxReverted.class,
                () -> registry(stub(new TxReceipt(0, List.of()))).getAnchoredRoot(TX, ISSUER, 7));
    }

    @Test
    void skipsNilLogs() {
        TxReceipt withNull = new TxReceipt(1, Arrays.asList((Log) null));
        assertFalse(anchored(registry(stub(withNull)), WANT));
        assertThrows(VcContractException.RootNotAnchored.class,
                () -> registry(stub(withNull)).getAnchoredRoot(TX, ISSUER, 7));
    }

    @Test
    void emptyRootIsAVerdictAndSkipsTheReceiptLookup() {
        assertFalse(anchored(registry(stub(ok())), ZERO32));
        assertFalse(anchored(registry(failing(new IllegalStateException("receipt source must not be called"))), ZERO32));
    }
}
