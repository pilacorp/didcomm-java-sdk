package com.pila.credential.vccontract;

import static com.pila.credential.vccontract.Fx.*;
import static org.junit.jupiter.api.Assertions.*;

import com.pila.credential.vccontract.ReceiptSource.TxReceipt;

import java.util.List;
import java.util.function.Consumer;

import org.junit.jupiter.api.Test;

class VerifyByTxTest {
    static final String LEAF = leaf(0xa1);
    static final String SIBLING = leaf(0xb2);
    static final String ROOT = CredentialRegistry.hashPair(LEAF, SIBLING);

    static VerifyByTxRequest req(Consumer<VerifyByTxRequest> mutate) {
        VerifyByTxRequest r = new VerifyByTxRequest();
        r.issuerAddress = ISSUER;
        r.leaf = LEAF;
        r.proof = List.of(SIBLING);
        r.txHash = leaf(0xcd);
        mutate.accept(r);
        return r;
    }

    static TxReceipt anchoring(String emitter) {
        return ok(batchLog(emitter, List.of(ISSUER), List.of(ROOT)));
    }

    static boolean verify(TxReceipt receipt, Consumer<VerifyByTxRequest> mutate, String... alsoTrust) {
        return registry(stub(receipt), alsoTrust).verifyVCHashByTx(req(mutate));
    }

    @Test
    void verdicts() {
        assertTrue(verify(anchoring(REGISTRY), r -> { }));
        assertFalse(verify(anchoring(REGISTRY), r -> r.proof = List.of(leaf(0xee))), "proof folds elsewhere");
        assertFalse(verify(anchoring(REGISTRY), r -> r.leaf = leaf(0xef)), "leaf not in tree");
        assertFalse(verify(anchoring(REGISTRY), r -> r.issuerAddress = OTHER), "different issuer");
        assertFalse(verify(new TxReceipt(0, List.of()), r -> { }), "reverted is a verdict, not a failure");
    }

    @Test
    void unminedIsAFailureNotAVerdict() {
        assertThrows(VcContractException.TxNotFound.class,
                () -> registry(failing(new VcContractException.TxNotFound())).verifyVCHashByTx(req(r -> { })));
    }

    @Test
    void previousContractsAnchoringsKeepVerifying() {
        assertTrue(verify(ok(legacySingleLog(LEGACY, ISSUER, ROOT)), r -> { }, LEGACY));
        assertTrue(verify(ok(legacyBatchLog(LEGACY, List.of(OTHER, ISSUER), List.of(leaf(1), ROOT))), r -> { }, LEGACY));
    }

    @Test
    void pinning() {
        assertTrue(verify(anchoring(LEGACY), r -> r.contractAddress = LEGACY, LEGACY));
        assertFalse(verify(anchoring(REGISTRY), r -> r.contractAddress = LEGACY, LEGACY));
        assertThrows(VcContractException.UntrustedContract.class,
                () -> verify(anchoring(REGISTRY), r -> r.contractAddress = ATTACKER));
    }

    @Test
    void malformedRequestsAreErrors() {
        assertThrows(IllegalArgumentException.class, () -> verify(anchoring(REGISTRY), r -> r.issuerAddress = "not-an-address"));
        assertThrows(IllegalArgumentException.class, () -> verify(anchoring(REGISTRY), r -> r.txHash = ""));
        assertThrows(IllegalArgumentException.class, () -> registry(stub(anchoring(REGISTRY))).verifyVCHashByTx(null));
        // right length, not hex: caught while decoding, still an error and never a verdict
        assertThrows(IllegalArgumentException.class, () -> verify(anchoring(REGISTRY), r -> r.leaf = "0x" + "zz".repeat(32)));
    }

    @Test
    void treeIndexIsIgnored() {
        assertTrue(verify(anchoring(REGISTRY), r -> r.treeIndex = 12345));
    }
}
