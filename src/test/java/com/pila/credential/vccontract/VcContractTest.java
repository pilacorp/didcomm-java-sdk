package com.pila.credential.vccontract;

import static com.pila.credential.vccontract.Fx.*;
import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.didv2.Hex;

import java.io.InputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

class VcContractTest {
    static final ObjectMapper JSON = new ObjectMapper();

    static JsonNode vectors() throws Exception {
        try (InputStream in = VcContractTest.class.getResourceAsStream("/vcanchor/go-vcanchor-vccontract-vectors.json")) {
            return JSON.readTree(in);
        }
    }

    static List<String> list(JsonNode n) {
        List<String> out = new ArrayList<>();
        n.forEach(x -> out.add(x.asText()));
        return out;
    }

    @Test
    void hexToBytes32() {
        assertEquals(leaf(0xcd), CredentialRegistry.hexToBytes32(leaf(0xcd)));
        assertEquals(leaf(0xcd), CredentialRegistry.hexToBytes32(leaf(0xcd).substring(2).toUpperCase()));
        assertThrows(IllegalArgumentException.class, () -> CredentialRegistry.hexToBytes32("0x1234"));
        assertThrows(IllegalArgumentException.class, () -> CredentialRegistry.hexToBytes32("0xzz"));
    }

    @Test
    void parseProof() {
        assertEquals(List.of(leaf(1), leaf(2)), CredentialRegistry.parseProof(List.of(leaf(1), leaf(2))));
        assertThrows(IllegalArgumentException.class, () -> CredentialRegistry.parseProof(List.of("0xzz")));
    }

    @Test
    void verifyRequestValidate() {
        VerifyRequest r = new VerifyRequest();
        r.issuerAddress = "0x1111111111111111111111111111111111111111";
        r.leaf = leaf(1);
        r.proof = List.of(leaf(2));
        r.validate();
        r.issuerAddress = "not-an-address";
        assertThrows(IllegalArgumentException.class, r::validate);
        r.issuerAddress = REGISTRY;
        r.leaf = "0xabcd";
        assertThrows(IllegalArgumentException.class, r::validate);
        assertThrows(IllegalArgumentException.class, new VerifyRequest()::validate);
        r.leaf = leaf(1);
        r.proof = List.of(leaf(2), "0xabcd");
        assertTrue(assertThrows(IllegalArgumentException.class, r::validate).getMessage().contains("index 1"));
    }

    @Test
    void verifyByTxRequestValidate() {
        VerifyByTxRequest r = new VerifyByTxRequest();
        r.issuerAddress = REGISTRY;
        r.leaf = leaf(1);
        r.proof = List.of(leaf(2));
        r.txHash = leaf(3);
        r.validate();
        r.txHash = "0xabcd";
        assertThrows(IllegalArgumentException.class, r::validate);
        r.txHash = "";
        assertThrows(IllegalArgumentException.class, r::validate);
        r.txHash = leaf(3);
        r.contractAddress = "nope";
        assertThrows(IllegalArgumentException.class, r::validate);
        r.contractAddress = LEGACY;
        r.validate();
        r.issuerAddress = "not-an-address";
        assertThrows(IllegalArgumentException.class, r::validate);
    }

    @Test
    void foldProofMerkle() {
        String a = leaf(0x0a), b = leaf(0x0b), c = leaf(0x0c), d = leaf(0x0d);
        String ab = CredentialRegistry.hashPair(a, b), cd = CredentialRegistry.hashPair(c, d);
        String root = CredentialRegistry.hashPair(ab, cd);
        assertEquals(root, CredentialRegistry.foldProof(a, List.of(b, cd)));
        assertEquals(root, CredentialRegistry.foldProof(b, List.of(a, cd)));
        assertEquals(root, CredentialRegistry.foldProof(c, List.of(d, ab)));
        assertEquals(root, CredentialRegistry.foldProof(d, List.of(c, ab)));
        assertNotEquals(root, CredentialRegistry.foldProof(a, List.of(leaf(0xff), cd)));
        assertNotEquals(root, CredentialRegistry.foldProof(leaf(0xee), List.of(b, cd)));
        // an inner node folds to the root too: the fold cannot tell inner nodes from leaves
        assertEquals(root, CredentialRegistry.foldProof(ab, List.of(cd)));
        // single leaf: root is the leaf
        assertEquals(leaf(0x42), CredentialRegistry.foldProof(leaf(0x42), List.of()));
        assertNotEquals(leaf(0x43), CredentialRegistry.foldProof(leaf(0x42), List.of()));
    }

    @Test
    void hashPairSortedAndKnownVector() {
        assertEquals(CredentialRegistry.hashPair(leaf(1), leaf(2)), CredentialRegistry.hashPair(leaf(2), leaf(1)));
        String a = leaf(0x0a), b = leaf(0x0b), c = leaf(0x0c), d = leaf(0x0d);
        assertEquals("0x0d0f9871649057367c9802ed72c3863f53b2d28ae3d10ece2d4ef0d2f9213784",
                CredentialRegistry.hashPair(a, b));
        assertEquals("0x94d1872730575cc36cfe8dc134c661933532c76cacf4512666feeb402206ca29",
                CredentialRegistry.hashPair(CredentialRegistry.hashPair(a, b), CredentialRegistry.hashPair(c, d)));
        // unsigned byte order: 0x80.. sorts after 0x01.. (signed compare would flip it)
        assertEquals(CredentialRegistry.hashPair(leaf(0x80), leaf(0x01)), CredentialRegistry.hashPair(leaf(0x01), leaf(0x80)));
    }

    @Test
    void goVectorTopicsCalldataFoldAndLogData() throws Exception {
        JsonNode v = vectors();
        v.get("topics").fields().forEachRemaining(e ->
                assertEquals(e.getValue().asText(), CredentialRegistry.EVENTS.get(e.getKey()).topic, e.getKey()));

        JsonNode fold = v.get("fold");
        String leaf = fold.get("leaf").asText();
        List<String> proof = list(fold.get("proof"));
        assertEquals(fold.get("folded").asText(), CredentialRegistry.foldProof(leaf, proof));
        assertEquals(fold.get("folded1").asText(), CredentialRegistry.foldProof(leaf, proof.subList(0, 1)));
        for (JsonNode b : v.get("batches")) {
            for (JsonNode r : b.get("receipts")) {
                assertEquals(r.get("root").asText(),
                        CredentialRegistry.foldProof(r.get("vc_hash").asText(), list(r.get("proof"))));
            }
        }

        JsonNode cd = v.get("calldata");
        assertEquals(cd.get("verifyVC").asText(),
                Hex.encode0x(CredentialRegistry.verifyVCCalldata(ISSUER, 5, leaf, proof)));
        assertEquals(cd.get("verifyVCEmpty").asText(),
                Hex.encode0x(CredentialRegistry.verifyVCCalldata(ISSUER, 0, leaf, List.of())));
        assertEquals(cd.get("getTreeRoot").asText(),
                Hex.encode0x(CredentialRegistry.treeCalldata("getTreeRoot(address,uint256)", ISSUER, 7)));
        assertEquals(cd.get("treeExists").asText(),
                Hex.encode0x(CredentialRegistry.treeCalldata("treeExists(address,uint256)", ISSUER, 7)));

        JsonNode ld = v.get("logdata");
        String sib = proof.get(0);
        assertEquals(ld.get("batch").asText(), encode(words(List.of(OTHER, ISSUER)), List.of(sib, leaf)));
        assertEquals(ld.get("issuer").asText(), encode(List.of(sib, leaf)));
        assertEquals(ld.get("legacySingle").asText(), encode(leaf));
        assertEquals(ld.get("legacyBatch").asText(), encode(words(List.of(OTHER, ISSUER)),
                List.of(BigInteger.valueOf(7), BigInteger.valueOf(8)), List.of(sib, leaf)));

        // the production decoder reads Go-produced bytes
        Object[] batch = CredentialRegistry.decodeData("BatchRootsAnchored", ld.get("batch").asText());
        assertEquals(List.of(OTHER, ISSUER), batch[0]);
        assertEquals(List.of(sib, leaf), batch[1]);
        Object[] mismatch = CredentialRegistry.decodeData("BatchRootsAnchored", ld.get("batchMismatch").asText());
        assertEquals(2, ((List<?>) mismatch[0]).size());
        assertEquals(1, ((List<?>) mismatch[1]).size());
        assertEquals(leaf, CredentialRegistry.decodeData("TreeUpdated", ld.get("legacySingle").asText())[0]);
    }

    @Test
    void decodeDataFailsClosedOnGarbage() {
        assertNull(CredentialRegistry.decodeData("BatchRootsAnchored", "0x1234"));
        assertNull(CredentialRegistry.decodeData("BatchRootsAnchored", "0x"));
        // offset pointing outside the data, and an absurd array length
        String badOffset = "0x" + Hex.encode(word(BigInteger.valueOf(1000))) + Hex.encode(word(BigInteger.valueOf(1000)));
        assertNull(CredentialRegistry.decodeData("BatchRootsAnchored", badOffset));
        String hugeLen = "0x" + Hex.encode(word(BigInteger.valueOf(64))) + Hex.encode(word(BigInteger.valueOf(64)))
                + Hex.encode(word(BigInteger.TWO.pow(200)));
        assertNull(CredentialRegistry.decodeData("BatchRootsAnchored", hugeLen));
    }
}
