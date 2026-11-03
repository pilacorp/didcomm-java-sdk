package com.pila.credential.didv2;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.verificationmethod.DIDDocument;
import com.pila.credential.didv2.didcontract.Abi;
import com.pila.credential.didv2.didcontract.Contract;
import com.pila.credential.didv2.subdid.GenerateSubDID;
import com.pila.credential.didv2.subdid.Merkle;
import com.pila.credential.didv2.subdid.SubDIDDocuments;
import com.pila.credential.didv2.subdid.SubDIDKeys;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DidV2VectorsTest {
    static final String ROOT_R1 = "did:nda:0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a";
    static final String SUB_ID = "0b8e6f3c-5a1d-4c27-9f40-3e2a7d91c6b5";
    static final String ROW1_PUB = "0x03354b9ae48c3cecaf6636ba88e321847edbf450a2777a012240d6d51705de73d7";
    static final String ROW1_PRIV = "0x46c9a6cf35b07f7d3f5d37f75bf671cc1251d9399a2db28e35b0942765cde8e8";
    static final String ROW1_SUB = "did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071";
    static final String ROOT_PRIV = "1111111111111111111111111111111111111111111111111111111111111111";
    static final String CREATE_JSON =
            "{\"@context\":[\"https://www.w3.org/ns/did/v1\",\"https://w3id.org/security/v1\"],\"id\":\"did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071\",\"controller\":\"did:nda:0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a\",\"verificationMethod\":[{\"id\":\"did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071#key-1\",\"type\":\"EcdsaSecp256k1VerificationKey2019\",\"controller\":\"did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071\",\"publicKeyHex\":\"0x03354b9ae48c3cecaf6636ba88e321847edbf450a2777a012240d6d51705de73d7\"}],\"authentication\":[\"did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071#key-1\"],\"assertionMethod\":[\"did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071#key-1\"],\"didDocumentMetadata\":{\"rootConsent\":\"0x45b815352a92764deec8dd6bd5f8842332f3e5548f75f803602ec99086537fb63bfa08f1ed32a03d3d33e7f455d4d78cb00877f4c8689c28f41b69dca8a5fa511c\",\"subId\":\"0b8e6f3c-5a1d-4c27-9f40-3e2a7d91c6b5\",\"type\":\"people\"}}";
    static final String CREATE_HASH = "0xd40e8cdf47ef809607d4be35edfc75aa9cbc3bda443ab93c706956ecdba3d8a8";
    static final String CREATE_SIG =
            "0x73ffc216c50a9cbdf28d8eac72954f337974e390e83427abe79d3ed5bea8ee7e602b23159cf8ce401bf7e5fc2de553568e9c3a9359267fc393e5033f7fa59ce61b";

    private static List<byte[]> fixtureLeaves(int n) {
        List<byte[]> leaves = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            byte[] leaf = new byte[32];
            Arrays.fill(leaf, (byte) (i + 1));
            leaves.add(leaf);
        }
        return leaves;
    }

    @Test
    void merkleRootVectors() throws Exception {
        assertEquals("0x0101010101010101010101010101010101010101010101010101010101010101",
                Hex.encode0x(Merkle.merkleRoot(fixtureLeaves(1))));
        assertEquals("0x346d8c96a2454213fcc0daff3c96ad0398148181b9fa6488f7ae2c0af5b20aa0",
                Hex.encode0x(Merkle.merkleRoot(fixtureLeaves(2))));
        assertEquals("0x1d614fa3c8de62938b0948972494f9a3858575db69ce1d34c77926f30732c981",
                Hex.encode0x(Merkle.merkleRoot(fixtureLeaves(3))));
        assertEquals("0x55d458ff264cc10cb4ef71d27a18db86f587999b2355cfa5eb5fccf8c973bced",
                Hex.encode0x(Merkle.merkleRoot(fixtureLeaves(5))));
    }

    @Test
    void revokedLeafVector() {
        assertEquals("0x83c91d2020210e4924defde940dcb4e63ec3f20bbad4229da6019faba05cc206",
                Hex.encode0x(Merkle.revokedLeaf("0x86b2efd244acb31eb238a65ca05476ab42558071")));
    }

    @Test
    void deriveSubDIDKeyVector() throws Exception {
        KeyPair kp = SubDIDKeys.deriveSubDIDKey(ROOT_PRIV, SUB_ID);
        assertEquals(ROW1_PRIV, kp.privateKeyHex);
        assertEquals(ROW1_PUB, kp.publicKeyHex);
        assertEquals("1073cf0910ef789f09d6e2aba3c17fa51465b3b65730dd733dcb1f9a090bd8f7", kp.p256X);
        assertEquals("2232ca28606fda872acc3dc833ab910cf94956654bac5c8c31dd5f3ff88099a9", kp.p256Y);
    }

    @Test
    void generateSubDIDVector() throws Exception {
        var res = GenerateSubDID.generate(ROOT_R1, SUB_ID, ROW1_PUB, Types.DID_TYPE_PEOPLE, null,
                new DefaultProvider(ROOT_PRIV), new DefaultProvider(ROW1_PRIV), List.of());
        assertEquals(ROW1_SUB, res.did);
        assertEquals("people", res.type);
        assertEquals(CREATE_SIG, res.signature);
        assertEquals(CREATE_JSON, Documents.marshalGoJSON(res.document));
        assertEquals(CREATE_HASH, SubDIDDocuments.docHash(res.document));
    }

    @Test
    void docHashFromFixtureJson() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        @SuppressWarnings("unchecked")
        Map<String, Object> m = mapper.readValue(CREATE_JSON, Map.class);
        DIDDocument doc = new DIDDocument();
        doc.setContext((List<String>) m.get("@context"));
        doc.setId((String) m.get("id"));
        doc.setController(m.get("controller"));
        doc.setAuthentication((List<String>) m.get("authentication"));
        doc.setAssertionMethod((List<String>) m.get("assertionMethod"));
        doc.setDidDocumentMetadata((Map<String, Object>) m.get("didDocumentMetadata"));
        List<Map<String, Object>> vms = (List<Map<String, Object>>) m.get("verificationMethod");
        var vm = new com.pila.credential.common.verificationmethod.VerificationMethodEntry();
        vm.setId((String) vms.get(0).get("id"));
        vm.setType((String) vms.get(0).get("type"));
        vm.setController((String) vms.get(0).get("controller"));
        vm.setPublicKeyHex((String) vms.get(0).get("publicKeyHex"));
        doc.setVerificationMethod(List.of(vm));
        assertEquals(CREATE_HASH, Documents.hashDIDDocument(doc));
    }

    @Test
    void writerTopicAndHasRoleSelector() {
        assertEquals("0x39edf358809bd8ab55bfce6add00fc1843a5c6e38ca5257fe7fb98b8bb145469",
                Contract.WRITER_ANCHOR_TOPIC0);
        assertEquals("91d14854", Hex.encode(Contract.HAS_ROLE_SELECTOR));
        assertEquals("0x6fc0b0d6b98862e3c914d0800fe475986e8788ba7b923ff2cc748cdb21b43243",
                Contract.SUBTREE_WRITER_ROLE);
    }

    @Test
    void decodeWriterAnchorsFromRegistryOnly() throws Exception {
        List<String> dids = List.of("0x00000000000000000000000000000000000003e8");
        List<BigInteger> idxs = List.of(BigInteger.ZERO);
        List<String> roots = List.of(Keccak256.hashHex(BigInteger.ZERO.toByteArray()));
        byte[] data = Abi.encodeWriterLogData(dids, idxs, roots);
        Contract.ReceiptLog other = new Contract.ReceiptLog();
        other.address = "0x0000000000000000000000000000000000000bad";
        other.topics = List.of(Contract.WRITER_ANCHOR_TOPIC0,
                "0x0000000000000000000000005b6a5525e2c2d2428554b04d24b3bb5c1f3f5ae3");
        other.data = Hex.encode0x(data);
        Contract.ReceiptLog ok = new Contract.ReceiptLog();
        ok.address = Config.DEFAULT_DID_SMC_ADDRESS;
        ok.topics = List.of(Contract.WRITER_ANCHOR_TOPIC0,
                "0x0000000000000000000000005b6a5525e2c2d2428554b04d24b3bb5c1f3f5ae3");
        ok.data = Hex.encode0x(data);
        var anchors = Contract.decodeWriterAnchors(List.of(other, ok), Config.DEFAULT_DID_SMC_ADDRESS);
        assertEquals(1, anchors.size());
        assertEquals("0x5b6a5525e2c2d2428554b04d24b3bb5c1f3f5ae3", anchors.get(0).writer);
        assertEquals(dids.get(0), anchors.get(0).did);
    }

    @Test
    void defaultsMatchGo() {
        assertEquals("https://rpc-new.pila.vn", Config.DEFAULT_RPC);
        assertEquals(704L, Config.DEFAULT_CHAIN_ID);
        assertEquals("0x75e7b09a24bce5a921babe27b62ec7bfe2230d6a", Config.DEFAULT_DID_SMC_ADDRESS);
        assertEquals("did:nda", Config.DEFAULT_METHOD);
    }

    @Test
    void createDidRawTxDoesNotSubmit() throws Exception {
        DefaultProvider signer = new DefaultProvider(ROOT_PRIV);
        Contract c = new Contract(Config.DEFAULT_RPC, Config.DEFAULT_DID_SMC_ADDRESS, Config.DEFAULT_CHAIN_ID);
        Issuer.IssuerSignature sig = new Issuer.IssuerSignature();
        sig.v = BigInteger.valueOf(27);
        sig.r = BigInteger.ONE;
        sig.s = BigInteger.TWO;
        var tx = c.createDIDTx(signer.getAddress(), 0, CREATE_HASH,
                "0x" + "11".repeat(32), sig, 0, signer);
        assertTrue(tx.txHex.length() > 20);
        assertTrue(tx.txHash.startsWith("0x"));
        assertEquals(64, Hex.normalize(tx.txHash).length());
    }
}
