package com.pila.credential.vccontract;

import static com.pila.credential.vccontract.Fx.*;
import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.junit.jupiter.api.Test;

@SuppressWarnings("deprecation")
class RegistryConfigTest {
    static final String ZERO = "0x0000000000000000000000000000000000000000";

    @Test
    void acceptsNoContractAddressAndTrustsAlsoTrust() {
        CredentialRegistry r = new CredentialRegistry(null, null, "", REGISTRY, LEGACY);
        assertTrue(r.trusts(REGISTRY));
        assertTrue(r.trusts(LEGACY));
        assertFalse(r.trusts(ATTACKER));
    }

    @Test
    void noContractAddressStillReadsLogs() {
        CredentialRegistry r = new CredentialRegistry(stub(ok(batchLog(REGISTRY, List.of(ISSUER), List.of(leaf(0xbb))))),
                null, "", REGISTRY);
        assertTrue(r.isRootAnchored(leaf(1), ISSUER, leaf(0xbb)));
    }

    @Test
    void viewFunctionsReportTheMissingContractAddress() {
        CredentialRegistry r = new CredentialRegistry(null, null, "", REGISTRY);
        VerifyRequest req = new VerifyRequest();
        req.issuerAddress = ISSUER;
        req.leaf = leaf(0xa1);
        req.proof = List.of(leaf(0xb2));
        assertThrows(VcContractException.NoContractAddress.class, () -> r.verifyVCHashOnChain(req));
        assertThrows(VcContractException.NoContractAddress.class, () -> r.getTreeRoot(ISSUER, 1));
        assertThrows(VcContractException.NoContractAddress.class, () -> r.hasTree(ISSUER, 1));
    }

    @Test
    void emptyTrustedSetBelievesEveryEmitter() {
        String forged = leaf(0xf0);
        CredentialRegistry open = new CredentialRegistry(stub(ok(singleLog(ATTACKER, ISSUER, forged))), null, "");
        assertTrue(open.trusts(ATTACKER));
        assertTrue(open.isRootAnchored(leaf(1), ISSUER, forged));
        CredentialRegistry pinned = new CredentialRegistry(stub(ok(singleLog(ATTACKER, ISSUER, forged))), null, REGISTRY);
        assertFalse(pinned.isRootAnchored(leaf(1), ISSUER, forged));
    }

    @Test
    void refusesTheZeroAddress() {
        assertThrows(IllegalArgumentException.class, () -> new CredentialRegistry(null, null, ZERO));
        assertThrows(IllegalArgumentException.class, () -> new CredentialRegistry(null, null, ZERO, REGISTRY));
        assertThrows(IllegalArgumentException.class, () -> new CredentialRegistry(null, null, REGISTRY, ZERO));
        assertThrows(IllegalArgumentException.class, () -> new CredentialRegistry(null, null, REGISTRY, LEGACY, ZERO));
    }

    @Test
    void refusesAMalformedAddressNamingTheEntry() {
        assertThrows(IllegalArgumentException.class, () -> new CredentialRegistry(null, null, "0xnope"));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> new CredentialRegistry(null, null, REGISTRY, LEGACY, "0xnope"));
        assertTrue(e.getMessage().contains("index 1"), e.getMessage());
    }

    @Test
    void connectRequiresRpcUrl() {
        assertThrows(IllegalArgumentException.class, () -> CredentialRegistry.connect("", REGISTRY));
    }

    @Test
    void verifyVCHashOnChainSendsGoIdenticalCalldataAndDecodesTheBool() throws Exception {
        var v = VcContractTest.vectors();
        String leaf = v.get("fold").get("leaf").asText();
        List<String> proof = VcContractTest.list(v.get("fold").get("proof"));
        List<String[]> calls = new java.util.ArrayList<>();
        String[] answer = {"0x" + "00".repeat(31) + "01"};
        CallSource src = (to, data) -> {
            calls.add(new String[] {to, data});
            return answer[0];
        };
        CredentialRegistry r = new CredentialRegistry(null, src, ISSUER.replace("abc", "abd"));
        VerifyRequest req = new VerifyRequest();
        req.issuerAddress = ISSUER;
        req.treeIndex = 5;
        req.leaf = leaf;
        req.proof = proof;
        assertTrue(r.verifyVCHashOnChain(req));
        assertEquals(ISSUER.replace("abc", "abd"), calls.get(0)[0]);
        assertEquals(v.get("calldata").get("verifyVC").asText(), calls.get(0)[1]);

        answer[0] = "0x" + "00".repeat(32);
        assertFalse(r.verifyVCHashOnChain(req));
        answer[0] = "0x" + "00".repeat(31) + "02";
        assertTrue(assertThrows(VcContractException.class, () -> r.verifyVCHashOnChain(req)).getMessage()
                .contains("improperly encoded boolean"));
        answer[0] = "0x";
        assertThrows(VcContractException.class, () -> r.verifyVCHashOnChain(req));

        answer[0] = "0x" + "11".repeat(32);
        assertEquals("0x" + "11".repeat(32), r.getTreeRoot(ISSUER, 7));
        assertEquals(v.get("calldata").get("getTreeRoot").asText(), calls.get(calls.size() - 1)[1]);
        answer[0] = "0x" + "00".repeat(31) + "01";
        assertTrue(r.hasTree(ISSUER, 7));
        assertEquals(v.get("calldata").get("treeExists").asText(), calls.get(calls.size() - 1)[1]);
        assertThrows(IllegalArgumentException.class, () -> r.getTreeRoot("nope", 7));
    }
}
