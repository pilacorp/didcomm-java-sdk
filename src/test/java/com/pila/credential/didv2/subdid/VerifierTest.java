package com.pila.credential.didv2.subdid;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.verificationmethod.DIDDocument;
import com.pila.credential.didv2.Config;
import com.pila.credential.didv2.Hex;
import com.pila.credential.didv2.didcontract.Abi;
import com.pila.credential.didv2.didcontract.ChainClient;
import com.pila.credential.didv2.didcontract.Contract;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Port of Go subdid/verifier_test.go (same fixtures, same fake node). */
public class VerifierTest {
    static final String ROOT_R1 = "did:nda:0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a";
    static final String ROOT_R2 = "did:nda:0x681248d5c48008ce14e5aebab76ce15476ad2509";
    static final String ROW1 = "did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071";
    static final String ROW2 = "did:nda:0x97c19e066bdaa1bc4788e3c2e6c35c7e7bfc73af";
    static final String ROOT_CONSENT_HIGH_S =
            "0x45b815352a92764deec8dd6bd5f8842332f3e5548f75f803602ec99086537fb6c405f70e12cd5fc2c2cc180baa2b28720aa664f1e6e00412cbb6f4b0279046f01b";
    static final String LEAF0 = "0xd40e8cdf47ef809607d4be35edfc75aa9cbc3bda443ab93c706956ecdba3d8a8";
    static final String LEAF1 = "0x6438c3e7fdf61c59a979cf95b40ab859cfdccb3c9f0ac33249699461ebfd8363";
    static final String LEAF2 = "0x6de90012fb12be46705b90a88415f7b49863cccefde9a86fd6943637efa2c1de";
    static final String ROOT = "0x740265369adf60c8f89f0a3b1f92feb3643c702d228a8894c900006384e59a9f";
    static final String PATH2 = "0xdf7c4019734ba03dd33f5d2f0365ef1dd49fc152631947e894b4c67ec69a01b2";
    static final String TREE_INDEX = "0xddbf3a86f0876cd98e1f4fbfa04c8bad4be62d65ca7da74c6d1c40738f936453";
    static final String ANCHOR_TX = "0x3c71000000000000000000000000000000000000000000000000000000000001";
    static final List<List<String>> PATHS = List.of(List.of(LEAF1, LEAF2), List.of(LEAF0, LEAF2), List.of(PATH2));
    static final String REGISTRY = "0x75e7b09a24bce5a921babe27b62ec7bfe2230d6a";
    static final String WRITER = "0x5b6a5525e2c2d2428554b04d24b3bb5c1f3f5ae3";
    static final String CREATE_JSON =
            "{\"@context\":[\"https://www.w3.org/ns/did/v1\",\"https://w3id.org/security/v1\"],\"id\":\"did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071\",\"controller\":\"did:nda:0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a\",\"verificationMethod\":[{\"id\":\"did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071#key-1\",\"type\":\"EcdsaSecp256k1VerificationKey2019\",\"controller\":\"did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071\",\"publicKeyHex\":\"0x03354b9ae48c3cecaf6636ba88e321847edbf450a2777a012240d6d51705de73d7\"}],\"authentication\":[\"did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071#key-1\"],\"assertionMethod\":[\"did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071#key-1\"],\"didDocumentMetadata\":{\"rootConsent\":\"0x45b815352a92764deec8dd6bd5f8842332f3e5548f75f803602ec99086537fb63bfa08f1ed32a03d3d33e7f455d4d78cb00877f4c8689c28f41b69dca8a5fa511c\",\"subId\":\"0b8e6f3c-5a1d-4c27-9f40-3e2a7d91c6b5\",\"type\":\"people\"}}";

    /** A node holding receipts at a DIDRegistry (Go fakeChain). */
    static final class FakeChain implements ChainClient {
        boolean down;
        long chainId = 704;
        Map<String, Contract.Receipt> receipts = new HashMap<>();
        Set<String> writers = new HashSet<>();

        @Override
        public BigInteger chainId() throws Exception {
            if (down) {
                throw new Exception("dial tcp: connection refused");
            }
            return BigInteger.valueOf(chainId);
        }

        @Override
        public Contract.Receipt transactionReceipt(String txHash) throws Exception {
            if (down) {
                throw new Exception("dial tcp: connection refused");
            }
            Contract.Receipt r = receipts.get(txHash);
            if (r == null) {
                throw new Exception("not found");
            }
            return r;
        }

        @Override
        public byte[] callContract(String to, byte[] data) throws Exception {
            if (down) {
                throw new Exception("dial tcp: connection refused");
            }
            if (!REGISTRY.equalsIgnoreCase(to)) {
                return new byte[0];
            }
            if (data.length != 68 || !Hex.encode(java.util.Arrays.copyOf(data, 4)).equals("91d14854")) {
                throw new Exception("execution reverted");
            }
            byte[] out = new byte[32];
            String role = Hex.encode0x(java.util.Arrays.copyOfRange(data, 4, 36));
            String account = "0x" + Hex.encode(java.util.Arrays.copyOfRange(data, 48, 68));
            if (role.equals(Contract.SUBTREE_WRITER_ROLE) && writers.contains(account)) {
                out[31] = 1;
            }
            return out;
        }

        @Override
        public BigInteger pendingNonceAt(String address) {
            return BigInteger.ZERO;
        }
    }

    static Contract.ReceiptLog writerLog(String emitter, String[]... entries) {
        List<String> dids = new ArrayList<>();
        List<BigInteger> idx = new ArrayList<>();
        List<String> roots = new ArrayList<>();
        for (String[] e : entries) {
            dids.add("0x" + ROOT_R1.substring(ROOT_R1.lastIndexOf(':') + 3));
            idx.add(new BigInteger(e[0].substring(2), 16));
            roots.add(e[1]);
        }
        Contract.ReceiptLog log = new Contract.ReceiptLog();
        log.address = emitter;
        log.topics = List.of(Contract.WRITER_ANCHOR_TOPIC0, "0x" + "00".repeat(12) + WRITER.substring(2));
        log.data = Hex.encode0x(Abi.encodeWriterLogData(dids, idx, roots));
        return log;
    }

    static String[] treeAnchor(String root) {
        return new String[] { TREE_INDEX, root };
    }

    static FakeChain provingChain(Contract.ReceiptLog... logs) {
        FakeChain c = new FakeChain();
        Contract.Receipt r = new Contract.Receipt();
        r.status = 1;
        r.logs = new ArrayList<>(List.of(logs.length == 0 ? new Contract.ReceiptLog[] { writerLog(REGISTRY, treeAnchor(ROOT)) } : logs));
        c.receipts.put(ANCHOR_TX, r);
        c.writers.add(WRITER);
        return c;
    }

    static Verifier verifier(Map<String, FakeChain> chains) {
        List<Verifier.Chain> cfg = new ArrayList<>();
        chains.forEach((code, client) -> cfg.add(new Verifier.Chain(code, 704, REGISTRY, client)));
        return new Verifier(cfg.toArray(Verifier.Chain[]::new));
    }

    static ProofResponse proofFor(String subDID, int index, String status, String... chains) {
        ProofResponse p = new ProofResponse();
        p.did = subDID;
        p.rootDid = ROOT_R1;
        p.treeIndex = TREE_INDEX;
        for (String c : chains) {
            ProofResponse.ChainProof e = new ProofResponse.ChainProof();
            e.chain = c;
            e.txHash = ANCHOR_TX;
            e.root = ROOT;
            e.path = new ArrayList<>(PATHS.get(index));
            e.status = status;
            p.chains.add(e);
        }
        return p;
    }

    static Verifier.VerifyRequest activeRequest(String chain, String... chains) throws Exception {
        Verifier.VerifyRequest r = new Verifier.VerifyRequest();
        r.subDID = ROW1;
        r.document = new ObjectMapper().readValue(CREATE_JSON, DIDDocument.class);
        r.proof = proofFor(ROW1, 0, "activated", chains);
        r.chain = chain;
        return r;
    }

    @Test
    void activeAndRevokedLeaves() throws Exception {
        Verifier v = verifier(Map.of("did", provingChain()));
        Verifier.Result res = v.verifySubDID(activeRequest("did", "did"));
        assertEquals(Verifier.Status.ACTIVE, res.status);
        assertEquals(null, res.reason);
        assertEquals("did", res.chain);
        assertEquals(ANCHOR_TX, res.txHash);

        Verifier.VerifyRequest rev = new Verifier.VerifyRequest();
        rev.subDID = ROW2;
        rev.proof = proofFor(ROW2, 1, "deactivated", "did");
        rev.chain = "did";
        assertEquals(Verifier.Status.REVOKED, v.verifySubDID(rev).status);

        Verifier.VerifyRequest noDoc = activeRequest("did", "did");
        noDoc.document = null;
        SubDIDException e = assertThrows(SubDIDException.class, () -> v.verifySubDID(noDoc));
        assertEquals(SubDIDException.Kind.DOCUMENT_REQUIRED, e.kind());
    }

    private void expectReason(Verifier.Reason reason, FakeChain chain, Consumer<Verifier.VerifyRequest> edit)
            throws Exception {
        Verifier.VerifyRequest req = activeRequest("did", "did");
        if (edit != null) {
            edit.accept(req);
        }
        Verifier.Result res = verifier(Map.of("did", chain != null ? chain : provingChain())).verifySubDID(req);
        assertEquals(Verifier.Status.INVALID, res.status, reason.code);
        assertEquals(reason, res.reason);
    }

    @Test
    void everyInvalidReason() throws Exception {
        expectReason(Verifier.Reason.RESPONSE_MISMATCH, null, r -> r.proof.did = ROW2);
        expectReason(Verifier.Reason.ID_MISMATCH, null, r -> r.document.setController(ROOT_R2));
        expectReason(Verifier.Reason.CONSENT_INVALID, null,
                r -> r.document.getDidDocumentMetadata().put("rootConsent", ROOT_CONSENT_HIGH_S));
        FakeChain failed = provingChain(writerLog(REGISTRY, treeAnchor(ROOT)));
        failed.receipts.get(ANCHOR_TX).status = 0;
        expectReason(Verifier.Reason.NO_ANCHOR, failed, null);
        expectReason(Verifier.Reason.ROOT_MISMATCH, provingChain(writerLog(REGISTRY, treeAnchor(LEAF0))), null);
        FakeChain noWriter = provingChain();
        noWriter.writers.clear();
        expectReason(Verifier.Reason.WRITER_REVOKED, noWriter, null);
        expectReason(Verifier.Reason.PROOF_MISMATCH, null, r -> r.proof.chains.get(0).path = new ArrayList<>(PATHS.get(1)));
        // anchored by another contract: no anchor
        expectReason(Verifier.Reason.NO_ANCHOR,
                provingChain(writerLog("0x0000000000000000000000000000000000000bad", treeAnchor(ROOT))), null);
    }

    @Test
    void onlyTheNamedChainIsRead() throws Exception {
        FakeChain down = new FakeChain();
        down.down = true;
        Verifier v = verifier(Map.of("did", down, "trace", provingChain()));
        SubDIDException e = assertThrows(SubDIDException.class,
                () -> v.verifySubDID(activeRequest("did", "did", "trace")));
        assertTrue(e.isChainUnavailable());
        Verifier.Result res = v.verifySubDID(activeRequest("trace", "did", "trace"));
        assertEquals(Verifier.Status.ACTIVE, res.status);
        assertEquals("trace", res.chain);
    }

    @Test
    void nodeOnAnotherChainId() {
        FakeChain node = provingChain();
        node.chainId = 705;
        SubDIDException e = assertThrows(SubDIDException.class,
                () -> verifier(Map.of("did", node)).verifySubDID(activeRequest("did", "did")));
        assertTrue(e.isChainMismatch() && e.isChainUnavailable());
    }

    @Test
    void namedChainMissingFromTheProof() {
        Verifier v = verifier(Map.of("did", provingChain(), "trace", provingChain()));
        SubDIDException e = assertThrows(SubDIDException.class, () -> v.verifySubDID(activeRequest("did", "trace")));
        assertEquals(SubDIDException.Kind.NOT_ANCHORED, e.kind());
    }

    @Test
    void lastEntryForTheTreeWins() throws Exception {
        FakeChain node = provingChain(writerLog(REGISTRY, treeAnchor(LEAF0)),
                writerLog(REGISTRY, treeAnchor(LEAF2), treeAnchor(ROOT)));
        assertEquals(Verifier.Status.ACTIVE, verifier(Map.of("did", node)).verifySubDID(activeRequest("did", "did")).status);
    }

    @Test
    void constructionAndRequestValidation() {
        FakeChain c = provingChain();
        assertThrows(IllegalArgumentException.class, () -> new Verifier());
        assertThrows(IllegalArgumentException.class, () -> new Verifier(new Verifier.Chain("", 704, REGISTRY, c)));
        assertThrows(IllegalArgumentException.class, () -> new Verifier(new Verifier.Chain("did", 0, REGISTRY, c)));
        assertThrows(IllegalArgumentException.class,
                () -> new Verifier(new Verifier.Chain("did", 704, "0x" + "00".repeat(20), c)));
        assertThrows(IllegalArgumentException.class, () -> new Verifier(new Verifier.Chain("did", 704, REGISTRY, null)));
        assertThrows(IllegalArgumentException.class, () -> new Verifier(new Verifier.Chain("did", 704, REGISTRY, c),
                new Verifier.Chain("did", 704, REGISTRY, c)));
        Verifier v = verifier(Map.of("did", c));
        Verifier.VerifyRequest r = new Verifier.VerifyRequest();
        r.subDID = ROW1;
        r.chain = "did";
        assertThrows(SubDIDException.class, () -> v.verifySubDID(r)); // proof is nil
        r.proof = proofFor(ROW1, 0, "activated", "did");
        r.subDID = "not a did";
        assertThrows(SubDIDException.class, () -> v.verifySubDID(r));
        r.subDID = ROW1;
        r.chain = "other";
        assertThrows(SubDIDException.class, () -> v.verifySubDID(r));
    }

    @Test
    void proofResponseParsesTheApiJson() throws Exception {
        ProofResponse p = ProofResponse.fromJson("{\"did\":\"" + ROW1 + "\",\"root_did\":\"" + ROOT_R1
                + "\",\"tree_index\":\"" + TREE_INDEX + "\",\"chains\":[{\"chain\":\"did\",\"tx_hash\":\"" + ANCHOR_TX
                + "\",\"root\":\"" + ROOT + "\",\"path\":[\"" + PATH2 + "\"],\"status\":\"activated\",\"extra\":1}]}");
        assertEquals(ROOT_R1, p.rootDid);
        assertEquals("activated", p.chains.get(0).status);
        assertEquals(List.of(PATH2), p.chains.get(0).path);
        assertEquals(Config.DEFAULT_DID_SMC_ADDRESS, REGISTRY);
    }
}
