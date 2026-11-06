package com.pila.credential.didv2;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.verificationmethod.DIDDocument;
import com.pila.credential.common.verificationmethod.JWK;
import com.pila.credential.common.verificationmethod.VerificationMethodEntry;
import com.pila.credential.did.VerificationPurpose;
import com.pila.credential.didv2.did.DIDDocumentOps;
import com.pila.credential.didv2.didcontract.Abi;
import com.pila.credential.didv2.didcontract.ChainClient;
import com.pila.credential.didv2.didcontract.Contract;
import com.pila.credential.didv2.didcontract.CreateDIDRequest;
import com.pila.credential.didv2.didcontract.JsonRpcClient;
import com.pila.credential.didv2.didcontract.SetDocumentHashByIssuerRequest;
import com.pila.credential.didv2.didcontract.SetDocumentHashRequest;
import com.pila.credential.didv2.subdid.Merkle;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Review rows 5.1-5.11, 5.13, 5.20-5.22, 5.27-5.31, 5.33, 6.15, 6.16, 6.18. Vectors in
 * go_review_vectors.tsv come from a Go program run against go-credential-sdk main (didv2/did, issuer,
 * didcontract); the in-repo comments say what each one pins.
 */
public class ReviewGapsDidV2Test {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String PRIV = "46c9a6cf35b07f7d3f5d37f75bf671cc1251d9399a2db28e35b0942765cde8e8";
    private static final String CAP7 = "0x" + "00".repeat(31) + "07";
    private static final String DOC_HASH = "0xd40e8cdf47ef809607d4be35edfc75aa9cbc3bda443ab93c706956ecdba3d8a8";
    private static final String ISSUER = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a";
    private static final String DID_ADDR = "0x86b2efd244acb31eb238a65ca05476ab42558071";

    private static List<String[]> vectors(String kind) throws Exception {
        List<String[]> out = new ArrayList<>();
        try (InputStream in = ReviewGapsDidV2Test.class.getResourceAsStream("/didv2/go_review_vectors.tsv")) {
            for (String line : new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\n")) {
                if (line.startsWith(kind + "\t")) {
                    out.add(line.split("\t", -1));
                }
            }
        }
        return out;
    }

    // ---- 5.8 / 5.9 / 5.10 / 5.11: Hash ----

    @Test
    void hashMatchesGoForRevokedJwkAndNilCases() throws Exception {
        List<String[]> hashes = vectors("HASH");
        assertTrue(hashes.size() == 29);
        for (String[] v : hashes) {
            DIDDocument doc = MAPPER.readValue(v[1], DIDDocument.class);
            if (v[2].startsWith("0x")) {
                assertEquals(v[2], Documents.hashDIDDocument(doc), v[1]);
            } else {
                assertThrows(Exception.class, () -> Documents.hashDIDDocument(doc), v[1]); // malformed revoked
            }
        }
    }

    @Test
    void hashOfNilDocumentIsAnError() {
        Exception e = assertThrows(Exception.class, () -> Documents.hashDIDDocument(null));
        assertEquals("DID document is nil", e.getMessage());
    }

    @Test
    void revokedIsWrittenAsRfc3339NanoNotIsoInstant() throws Exception {
        assertEquals("2026-01-02T03:04:05.12Z", Rfc3339Nano.normalize("2026-01-02T03:04:05.120Z"));
        assertEquals("2026-01-02T10:04:05.123456789+07:00", Rfc3339Nano.normalize("2026-01-02T10:04:05.123456789+07:00"));
        assertEquals("2026-01-02T03:04:05Z", Rfc3339Nano.normalize("2026-01-02T03:04:05.000+00:00"));
        assertEquals("2026-01-02T03:04:05.5Z", Rfc3339Nano.normalize("2026-01-02T03:04:05,5Z"));
        assertEquals("2026-01-02T03:04:05+08:00", Rfc3339Nano.normalize("2026-01-02T03:04:05+07:60"));
        assertEquals("2026-01-02T03:04:05.123456789Z", Rfc3339Nano.normalize("2026-01-02T03:04:05.1234567891234Z"));
        assertThrows(Exception.class, () -> Rfc3339Nano.normalize("2026-01-02t03:04:05Z"));
        assertThrows(Exception.class, () -> Rfc3339Nano.normalize("2026-01-02T03:04:05"));
        assertThrows(Exception.class, () -> Rfc3339Nano.normalize("2026-02-30T03:04:05Z"));
        assertThrows(Exception.class, () -> Rfc3339Nano.normalize("2026-01-02T03:04:60Z"));
        assertThrows(Exception.class, () -> Rfc3339Nano.normalize("2026-01-02T03:04:05+24:00"));
        assertEquals("2026-01-02T03:04:05.000000500Z".replace("000000500", "0000005"),
                Rfc3339Nano.format(Instant.parse("2026-01-02T03:04:05.0000005Z")));
        assertEquals("2026-01-02T10:04:05+07:00",
                Rfc3339Nano.format(OffsetDateTime.parse("2026-01-02T10:04:05+07:00")));
    }

    @Test
    void revokeAndRotateWriteGoTimeText() throws Exception {
        DIDDocument doc = Documents.generateDIDDocument(
                "0x03354b9ae48c3cecaf6636ba88e321847edbf450a2777a012240d6d51705de73d7",
                "did:nda:" + DID_ADDR, "", "did:nda:" + ISSUER, Types.DID_TYPE_PEOPLE, null, List.of());
        String secondKey = Hex.encode0x(Secp256k1.publicFromPrivate(Hex.decode("00".repeat(31) + "02"), true));
        DIDDocumentOps.revokeVerificationMethod(doc, "#key-1", "superseded",
                Instant.parse("2026-01-02T03:04:05.120Z"));
        assertEquals("2026-01-02T03:04:05.12Z", doc.getVerificationMethod().get(0).getRevoked());
        assertThrows(Exception.class, () -> DIDDocumentOps.revokeVerificationMethod(doc, "#key-1", "x", (Instant) null));
        VerificationMethodEntry fresh = new VerificationMethodEntry();
        fresh.setPublicKeyHex(secondKey);
        DIDDocument doc2 = Documents.generateDIDDocument(
                "0x03354b9ae48c3cecaf6636ba88e321847edbf450a2777a012240d6d51705de73d7",
                "did:nda:" + DID_ADDR, "", "did:nda:" + ISSUER, Types.DID_TYPE_PEOPLE, null, List.of());
        String newId = DIDDocumentOps.rotateVerificationMethod(doc2, "#key-1", fresh, "",
                OffsetDateTime.parse("2026-01-02T10:04:05.5+07:00"));
        assertEquals("did:nda:" + DID_ADDR + "#key-2", newId);
        assertEquals("2026-01-02T10:04:05.5+07:00", doc2.getVerificationMethod().get(0).getRevoked());
        assertEquals("superseded", doc2.getVerificationMethod().get(0).getRevocationReason());
        // a document with a revoked VM still hashes (the stored text is a valid RFC3339 value)
        assertTrue(Documents.hashDIDDocument(doc2).startsWith("0x"));
    }

    @Test
    void jwkAnyKeyBlocksPublicKeyJwkOnPublish() {
        VerificationMethodEntry vm = new VerificationMethodEntry();
        vm.setPublicKeyHex("0x03354b9ae48c3cecaf6636ba88e321847edbf450a2777a012240d6d51705de73d7");
        JWK extra = new JWK();
        extra.putAdditional("kid", "k1"); // none of kty/crv/x set, but the map is not empty
        vm.setPublicKeyJwk(extra);
        assertThrows(Exception.class, () -> DIDDocumentOps.vmTypeFor(vm));
        vm.setPublicKeyJwk(new JWK()); // an empty map is nothing
        assertDoesNotThrowType(vm);
    }

    private static void assertDoesNotThrowType(VerificationMethodEntry vm) {
        try {
            assertEquals("EcdsaSecp256k1VerificationKey2019", DIDDocumentOps.vmTypeFor(vm));
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    @Test
    void nextSequentialKidUses64BitAtoi() throws Exception {
        DIDDocument doc = Documents.generateDIDDocument(
                "0x03354b9ae48c3cecaf6636ba88e321847edbf450a2777a012240d6d51705de73d7",
                "did:nda:" + DID_ADDR, "", "did:nda:" + ISSUER, Types.DID_TYPE_PEOPLE, null, List.of());
        doc.getVerificationMethod().get(0).setId("did:nda:" + DID_ADDR + "#key-4294967296"); // > int32
        VerificationMethodEntry vm = new VerificationMethodEntry();
        vm.setPublicKeyHex(Hex.encode0x(Secp256k1.publicFromPrivate(Hex.decode("00".repeat(31) + "02"), true)));
        assertEquals("did:nda:" + DID_ADDR + "#key-4294967297",
                DIDDocumentOps.addVerificationMethod(doc, vm, List.of(VerificationPurpose.AUTHENTICATION)));
    }

    @Test
    void generateDIDDocumentIsNullOnInvalidSpecsAndSpecsArePublic() throws Exception {
        VerificationMethodEntry vm = Documents.newSecp256k1VM("did:nda:" + DID_ADDR, "#key-2",
                "0x03354b9ae48c3cecaf6636ba88e321847edbf450a2777a012240d6d51705de73d7");
        Documents.VmSpec ok = Documents.newSpec(vm, VerificationPurpose.AUTHENTICATION);
        assertEquals(List.of(VerificationPurpose.AUTHENTICATION), ok.purposes);
        Documents.Built built = Documents.newVerificationMethods(List.of(ok));
        assertEquals(List.of(vm.getId()), built.authentication);
        assertTrue(built.assertionMethod.isEmpty());
        Documents.VmSpec bad = new Documents.VmSpec(vm, java.util.Arrays.asList((VerificationPurpose) null));
        assertNull(Documents.generateDIDDocument("0x03354b9ae48c3cecaf6636ba88e321847edbf450a2777a012240d6d51705de73d7",
                "did:nda:" + DID_ADDR, "", "did:nda:" + ISSUER, Types.DID_TYPE_PEOPLE, null, List.of(bad)));
        assertThrows(Exception.class, () -> Documents.validateDIDDocument(null));
    }

    @Test
    void p256MultikeyVmFromPublicKeyObject() throws Exception {
        java.security.KeyPairGenerator g = java.security.KeyPairGenerator.getInstance("EC", "BC");
        g.initialize(new java.security.spec.ECGenParameterSpec("prime256v1"));
        var kp = g.generateKeyPair();
        var pub = (java.security.interfaces.ECPublicKey) kp.getPublic();
        VerificationMethodEntry vm = Documents.newP256MultikeyVM("did:nda:" + DID_ADDR, "#key-2", pub);
        assertEquals("did:nda:" + DID_ADDR + "#key-2", vm.getId());
        assertEquals("Multikey", vm.getType());
        String x = String.format("%064x", pub.getW().getAffineX());
        String y = String.format("%064x", pub.getW().getAffineY());
        assertEquals(Documents.newP256MultikeyVM("did:nda:" + DID_ADDR, "#key-2", x, y).getPublicKeyMultibase(),
                vm.getPublicKeyMultibase());
        assertThrows(Exception.class, () -> Documents.newP256MultikeyVM("did:nda:" + DID_ADDR, "#k",
                (java.security.interfaces.ECPublicKey) null));
    }

    // ---- 5.4 / 5.31: issuer payload ----

    @Test
    void issuerPayloadEncodesEpochLikeGo() throws Exception {
        for (String[] v : vectors("PAYLOAD")) {
            Issuer.IssueDIDPayload p = new Issuer.IssueDIDPayload();
            p.contractAddress = "0x75e7b09a24bce5a921babe27b62ec7bfe2230d6a";
            p.issuerAddress = ISSUER;
            p.didAddress = DID_ADDR;
            p.didType = 1;
            p.epoch = Long.parseUnsignedLong(v[1]);
            p.capId = CAP7;
            assertEquals(v[2], Hex.encode(Issuer.buildIssueDIDPayload(p)), "epoch " + v[1]);
        }
    }

    @Test
    void capIdMustBeExactly66CharactersAndAddressesStrictHex() throws Exception {
        Issuer.IssueDIDPayload p = new Issuer.IssueDIDPayload();
        p.contractAddress = "0x75e7b09a24bce5a921babe27b62ec7bfe2230d6a";
        p.issuerAddress = ISSUER;
        p.didAddress = DID_ADDR;
        p.capId = "00".repeat(32); // 64 hex chars without 0x: Go refuses
        assertThrows(Exception.class, () -> Issuer.buildIssueDIDPayload(p));
        p.capId = "0X" + "00".repeat(32); // right length, but Go's TrimPrefix("0x") leaves the X
        assertThrows(Exception.class, () -> Issuer.buildIssueDIDPayload(p));
        p.capId = "0x" + "00".repeat(32);
        assertNotNull(Issuer.buildIssueDIDPayload(p));
        assertTrue(Issuer.isAddress("0X" + DID_ADDR.substring(2))); // common.IsHexAddress takes 0X
        assertTrue(!Issuer.isAddress("0x" + "g".repeat(40)));
        assertTrue(!Issuer.isAddress("0x" + "٣".repeat(40)));
        assertTrue(!Issuer.isAddress(DID_ADDR.substring(0, 41)));
        p.didAddress = "0x" + "zz".repeat(20);
        assertThrows(Exception.class, () -> Issuer.buildIssueDIDPayload(p));
    }

    // ---- 5.5 / 5.6 / 5.7 keys, addresses ----

    @Test
    void keyGenerationIsInRangeAndProviderRejectsBadScalars() {
        for (int i = 0; i < 20; i++) {
            KeyPair kp = Documents.generateECDSAKeyPair();
            BigInteger d = new BigInteger(1, Hex.decode(kp.privateKeyHex));
            assertTrue(d.signum() > 0 && d.compareTo(Secp256k1.N) < 0);
            assertEquals(kp.address, new DefaultProvider(kp.privateKeyHex).getAddress());
        }
        assertThrows(IllegalArgumentException.class, () -> new DefaultProvider("00".repeat(32)));
        assertThrows(IllegalArgumentException.class, () -> new DefaultProvider(Secp256k1.N.toString(16)));
        assertThrows(IllegalArgumentException.class,
                () -> new DefaultProvider("ff".repeat(32))); // above the order
        assertThrows(IllegalArgumentException.class, () -> new DefaultProvider("0X" + PRIV)); // Go trims "0x" only
        assertNotNull(new DefaultProvider("0x" + PRIV));
    }

    @Test
    void addressFromPublicKeyHexIsStrict() throws Exception {
        String compressed = "0x03354b9ae48c3cecaf6636ba88e321847edbf450a2777a012240d6d51705de73d7";
        assertEquals(DID_ADDR, Documents.addressFromPublicKeyHex(compressed));
        byte[] unc = Secp256k1.decompress(Hex.decode(compressed));
        assertEquals(DID_ADDR, Documents.addressFromPublicKeyHex(Hex.encode0x(unc)));
        byte[] off = unc.clone();
        off[64] ^= 1; // off-curve
        assertThrows(Exception.class, () -> Documents.addressFromPublicKeyHex(Hex.encode0x(off)));
        assertThrows(Exception.class, () -> Documents.addressFromPublicKeyHex("0X" + compressed.substring(2)));
        assertThrows(Exception.class, () -> Documents.addressFromPublicKeyHex("0x٠" + compressed.substring(3)));
        assertThrows(Exception.class, () -> Documents.addressFromPublicKeyHex("0x04" + "00".repeat(32)));
    }

    // ---- 5.27-5.29: contract requests, EIP-155, writer logs ----

    private static Signer shifted(DefaultProvider p) {
        return new Signer() {
            @Override
            public byte[] sign(byte[] digest32) throws Exception {
                byte[] s = p.sign(digest32);
                s[64] += 27;
                return s;
            }

            @Override
            public String getAddress() {
                return p.getAddress();
            }
        };
    }

    @Test
    void rawTransactionMatchesGoAndKeepsTheSignersV() throws Exception {
        DefaultProvider signer = new DefaultProvider(PRIV);
        Contract c = new Contract(Config.DEFAULT_RPC, Config.DEFAULT_DID_SMC_ADDRESS, Config.DEFAULT_CHAIN_ID);
        Issuer.IssuerSignature sig = new Issuer.IssuerSignature();
        sig.v = BigInteger.valueOf(27);
        sig.r = BigInteger.ONE;
        sig.s = BigInteger.TWO;
        CreateDIDRequest req = new CreateDIDRequest();
        req.issuerAddress = ISSUER;
        req.issuerSig = sig;
        req.docHash = DOC_HASH;
        req.capId = CAP7;
        req.didType = 0;
        req.nonce = 3;
        for (String[] v : vectors("TX")) {
            var tx = c.createDIDTx(req, v[1].equals("normal") ? signer : shifted(signer));
            assertEquals(v[2], tx.txHex, v[1]);
            assertEquals(v[3], tx.txHash, v[1]);
        }
        Signer short64 = new Signer() {
            @Override
            public byte[] sign(byte[] d) {
                return new byte[64];
            }

            @Override
            public String getAddress() {
                return signer.getAddress();
            }
        };
        assertThrows(Exception.class, () -> c.createDIDTx(req, short64)); // WithSignature needs 65 bytes
    }

    @Test
    void requestsValidateAddressesAndHexLengths() throws Exception {
        Issuer.IssuerSignature sig = new Issuer.IssuerSignature();
        sig.v = BigInteger.valueOf(27);
        sig.r = BigInteger.ONE;
        sig.s = BigInteger.TWO;
        CreateDIDRequest r = new CreateDIDRequest();
        r.issuerAddress = ISSUER;
        r.issuerSig = sig;
        r.docHash = DOC_HASH;
        r.capId = CAP7;
        r.validate();
        r.issuerAddress = "0x1234"; // Abi.addressWord used to pad this silently
        assertThrows(Exception.class, r::validate);
        r.issuerAddress = ISSUER;
        r.docHash = DOC_HASH.substring(2); // 64 chars, no prefix is fine
        r.validate();
        r.docHash = "0X" + DOC_HASH.substring(2); // 0X is not a prefix for the length rule: 66 chars
        assertThrows(Exception.class, r::validate);
        r.docHash = DOC_HASH;
        r.capId = CAP7 + "00";
        assertThrows(Exception.class, r::validate);
        r.capId = CAP7;
        r.issuerSig = null;
        assertThrows(Exception.class, r::validate);

        SetDocumentHashRequest s = new SetDocumentHashRequest();
        s.didAddress = DID_ADDR;
        s.docHash = DOC_HASH;
        s.capId = CAP7;
        s.issuerSig = sig;
        s.validate();
        s.didAddress = "not-an-address";
        assertThrows(Exception.class, s::validate);

        SetDocumentHashByIssuerRequest b = new SetDocumentHashByIssuerRequest();
        b.didAddress = DID_ADDR;
        b.docHash = DOC_HASH;
        b.validate();
        b.docHash = "0x12";
        assertThrows(Exception.class, b::validate);

        Contract c = new Contract(Config.DEFAULT_RPC, Config.DEFAULT_DID_SMC_ADDRESS, Config.DEFAULT_CHAIN_ID);
        DefaultProvider signer = new DefaultProvider(PRIV);
        assertThrows(Exception.class, () -> c.setDocumentHashByIssuerTx(b, signer));
        assertThrows(Exception.class, () -> c.setDocumentHashByIssuerTx((SetDocumentHashByIssuerRequest) null, signer));
        b.docHash = DOC_HASH;
        assertNotNull(c.setDocumentHashByIssuerTx(b, signer).txHex);
    }

    @Test
    void writerLogDecodingChecksBounds() throws Exception {
        String topic = "0x0000000000000000000000005b6a5525e2c2d2428554b04d24b3bb5c1f3f5ae3";
        byte[] good = Abi.encodeWriterLogData(List.of("0x00000000000000000000000000000000000003e8"),
                List.of(BigInteger.ZERO), List.of(DOC_HASH));
        assertEquals(1, Abi.decodeWriterLog(topic, good).size());
        // an offset past the data
        byte[] badOffset = good.clone();
        badOffset[31] = (byte) 0xff;
        badOffset[30] = (byte) 0xff;
        assertThrows(IllegalArgumentException.class, () -> Abi.decodeWriterLog(topic, badOffset));
        // an array length (2^31) larger than the data
        byte[] hugeLen = good.clone();
        hugeLen[96 + 28] = (byte) 0x80;
        assertThrows(IllegalArgumentException.class, () -> Abi.decodeWriterLog(topic, hugeLen));
        // an array length that fits an int but not the data (intValue() used to truncate it silently)
        byte[] longLen = good.clone();
        longLen[96 + 31] = 5;
        assertThrows(IllegalArgumentException.class, () -> Abi.decodeWriterLog(topic, longLen));
        // truncated data: the head alone
        assertThrows(IllegalArgumentException.class, () -> Abi.decodeWriterLog(topic, new byte[40]));
        assertThrows(IllegalArgumentException.class,
                () -> Abi.decodeWriterLog(topic, java.util.Arrays.copyOf(good, good.length - 1)));
        // 2^32 + 96 as an offset would wrap to 96 under intValue()
        byte[] wrap = good.clone();
        wrap[27] = 1;
        assertThrows(IllegalArgumentException.class, () -> Abi.decodeWriterLog(topic, wrap));
    }

    @Test
    void hasRoleNeedsAnExactBoolWord() throws Exception {
        byte[] t = new byte[32];
        t[31] = 1;
        assertTrue(Contract.decodeHasRole(t));
        assertTrue(!Contract.decodeHasRole(new byte[32]));
        byte[] two = new byte[32];
        two[31] = 2;
        assertThrows(Exception.class, () -> Contract.decodeHasRole(two));
        byte[] high = new byte[32];
        high[0] = 1;
        assertThrows(Exception.class, () -> Contract.decodeHasRole(high));
        assertThrows(Exception.class, () -> Contract.decodeHasRole(new byte[31]));
    }

    @Test
    void hasRolePerformsTheRpcCall() throws Exception {
        byte[][] seen = new byte[1][];
        ChainClient chain = new FakeChain() {
            @Override
            public byte[] callContract(String to, byte[] data) {
                seen[0] = data;
                byte[] out = new byte[32];
                out[31] = 1;
                return out;
            }
        };
        assertTrue(Contract.hasRole(chain, Config.DEFAULT_DID_SMC_ADDRESS, Contract.SUBTREE_WRITER_ROLE,
                "0x5b6a5525e2c2d2428554b04d24b3bb5c1f3f5ae3"));
        assertEquals(68, seen[0].length);
        assertEquals("91d14854", Hex.encode(java.util.Arrays.copyOf(seen[0], 4)));
    }

    // ---- 5.2 / 5.3 / 5.1 / 6.15: RPC, sync, config resolution ----

    abstract static class FakeChain implements ChainClient {
        @Override
        public BigInteger chainId() {
            return BigInteger.valueOf(704);
        }

        @Override
        public Contract.Receipt transactionReceipt(String txHash) throws Exception {
            throw new Exception("not found");
        }

        @Override
        public byte[] callContract(String to, byte[] data) throws Exception {
            throw new Exception("unexpected eth_call");
        }

        @Override
        public BigInteger pendingNonceAt(String address) throws Exception {
            throw new Exception("unexpected nonce read");
        }
    }

    @Test
    void jsonRpcClientSpeaksEthRpcThroughAnInjectedTransport() throws Exception {
        List<JsonNode> requests = new ArrayList<>();
        JsonRpcClient rpc = new JsonRpcClient("http://node", (url, body) -> {
            assertEquals("http://node", url);
            JsonNode req = MAPPER.readTree(body);
            requests.add(req);
            return switch (req.get("method").asText()) {
                case "eth_getTransactionCount" -> "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x2a\"}";
                case "eth_call" -> "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x" + "00".repeat(31) + "07\"}";
                case "eth_chainId" -> "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x2c0\"}";
                default -> "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601,\"message\":\"nope\"}}";
            };
        });
        Contract c = new Contract("http://node", Config.DEFAULT_DID_SMC_ADDRESS, Config.DEFAULT_CHAIN_ID,
                Contract.DEFAULT_GAS_LIMIT, BigInteger.ZERO, rpc);
        assertEquals(42, c.getNonce(DID_ADDR));
        assertEquals("pending", requests.get(0).get("params").get(1).asText());
        assertEquals(7, c.getCapabilityEpoch(ISSUER));
        JsonNode call = requests.get(1).get("params").get(0);
        assertEquals(Config.DEFAULT_DID_SMC_ADDRESS, call.get("to").asText());
        assertEquals("0x" + Hex.encode(Contract.GET_CAPABILITY_EPOCH_SELECTOR) + "00".repeat(12) + ISSUER.substring(2),
                call.get("data").asText());
        assertEquals(BigInteger.valueOf(704), rpc.chainId());
        Exception e = assertThrows(Exception.class, () -> rpc.transactionReceipt("0x" + "00".repeat(32)));
        assertTrue(e.getMessage().contains("nope"));
        // no RPC client: reads fail, transactions still build
        Contract offline = new Contract("", Config.DEFAULT_DID_SMC_ADDRESS, Config.DEFAULT_CHAIN_ID);
        assertThrows(Exception.class, () -> offline.getNonce(DID_ADDR));
        assertThrows(Exception.class, () -> offline.getCapabilityEpoch(ISSUER));
    }

    @Test
    void generatorResolvesConfigGeneratesCapIdAndSyncsEpochAndNonce() throws Exception {
        List<String> calls = new ArrayList<>();
        ChainClient chain = new FakeChain() {
            @Override
            public byte[] callContract(String to, byte[] data) {
                calls.add("epoch:" + Hex.encode(data));
                byte[] out = new byte[32];
                out[31] = 9;
                return out;
            }

            @Override
            public BigInteger pendingNonceAt(String address) {
                calls.add("nonce:" + address);
                return BigInteger.valueOf(17);
            }
        };
        DefaultProvider issuer = new DefaultProvider("11".repeat(32));
        DefaultProvider didSigner = new DefaultProvider(PRIV);
        DIDGenerator gen = new DIDGenerator(Config.withChainClient(chain), Config.withIssuerSignerProvider(issuer),
                Config.withDIDSignerProvider(didSigner));
        // no capId, no epoch/nonce configured: capId is generated; sync pulls epoch 9 and nonce 17
        Issuer.IssuerSignature synced = gen.generateIssuerSignature(0, DID_ADDR, issuer.getAddress(),
                Config.withSyncEpoch(true), Config.withCapID(CAP7));
        Issuer.IssueDIDPayload p = new Issuer.IssueDIDPayload();
        p.contractAddress = Config.DEFAULT_DID_SMC_ADDRESS;
        p.issuerAddress = issuer.getAddress();
        p.didAddress = DID_ADDR;
        p.didType = 0;
        p.epoch = 9;
        p.capId = CAP7;
        Issuer.IssuerSignature expected = Issuer.generateIssueDIDSignature(p, issuer);
        assertEquals(expected.r, synced.r);
        assertEquals(expected.s, synced.s);
        p.epoch = 0;
        Issuer.IssuerSignature unsynced = Issuer.generateIssueDIDSignature(p, issuer);
        assertTrue(!unsynced.r.equals(synced.r), "the synced epoch must change the signed payload");

        var tx = gen.generateDIDCreateTransaction(0, DOC_HASH, DID_ADDR, issuer.getAddress(), synced,
                Config.withSyncNonce(true), Config.withCapID(CAP7));
        assertTrue(calls.contains("nonce:" + DID_ADDR));
        Contract plain = new Contract(Config.DEFAULT_RPC, Config.DEFAULT_DID_SMC_ADDRESS, Config.DEFAULT_CHAIN_ID);
        assertEquals(plain.createDIDTx(issuer.getAddress(), 0, DOC_HASH, CAP7, synced, 17, didSigner).txHex, tx.txHex);

        // setDocumentHashByIssuer syncs the ISSUER's nonce
        gen.generateSetDocumentHashByIssuerTransaction(DOC_HASH, DID_ADDR, Config.withSyncNonce(true));
        assertTrue(calls.contains("nonce:" + issuer.getAddress()));

        // a full generateDIDTX: capId auto-generated (66 chars), result carries doc, hash-bound tx
        DIDGenerator.DIDTxResult res = gen.generateDIDTX(DIDType.PEOPLE,
                "0x03354b9ae48c3cecaf6636ba88e321847edbf450a2777a012240d6d51705de73d7", "", Map.of("k", "v"),
                Config.withSyncEpoch(true), Config.withSyncNonce(true));
        assertEquals("did:nda:" + DID_ADDR, res.did);
        assertNotNull(res.transaction.txHex);

        // generateDID returns the Secret
        DIDGenerator.DIDTxResult made = gen.generateDID(DIDType.ITEM, "", null, Config.withP256VerificationMethod());
        assertEquals(made.secretPrivateKeyHex, made.secret.privateKeyHex);
        assertEquals(2, made.document.getVerificationMethod().size());
    }

    @Test
    void namedOptionsAndDidConfigCopy() {
        DefaultProvider s = new DefaultProvider(PRIV);
        Config base = Config.apply(Config.withRPC("http://x"), Config.withDIDChainID(9),
                Config.withDIDAddressSMC("0xABCDEF0123456789ABCDEF0123456789ABCDEF01"), Config.withMethod("did:test"),
                Config.withEpoch(5), Config.withNonce(6), Config.withCapID("c"), Config.withSyncEpoch(true),
                Config.withSyncNonce(true), Config.withIssuerSignerProvider(s), Config.withDIDSignerProvider(s),
                Config.withP256VerificationMethod());
        Config copy = Config.apply(Config.withDIDConfig(base));
        assertEquals("http://x", copy.rpc);
        assertEquals(9, copy.chainId);
        assertEquals("0xabcdef0123456789abcdef0123456789abcdef01", copy.didSmcAddr); // lower-cased
        assertEquals("did:test", copy.method);
        assertEquals(5, copy.epoch);
        assertEquals(6, copy.nonce);
        assertEquals("c", copy.capId);
        assertTrue(copy.syncEpoch && copy.syncNonce && copy.enableP256VM);
        assertTrue(copy.issuerSigner == s && copy.didSigner == s);
        assertEquals(DIDType.LOCATION.value, 2);
        assertEquals("activity", DIDType.ACTIVITY.label());
    }

    @Test
    void generatorRejectsABadContractConfigAtConstruction() {
        assertThrows(IllegalArgumentException.class, () -> new DIDGenerator(Config.withDIDAddressSMC("0x1234")));
        assertThrows(IllegalArgumentException.class, () -> new DIDGenerator(Config.withDIDChainID(0)));
    }

    // ---- 5.33 Merkle fixed-size ----

    @Test
    void merkleProofRefusesWrongSizedInput() {
        byte[] leaf = new byte[32];
        byte[] root = new byte[32];
        assertThrows(IllegalArgumentException.class, () -> Merkle.verifyProof(new byte[31], List.of(), root));
        assertThrows(IllegalArgumentException.class, () -> Merkle.verifyProof(leaf, List.of(new byte[33]), root));
        assertThrows(IllegalArgumentException.class, () -> Merkle.verifyProof(leaf, List.of(), new byte[5]));
        assertTrue(Merkle.verifyProof(leaf, List.of(), root));
        assertThrows(IllegalArgumentException.class, () -> Merkle.revokedLeaf("0x1234"));
        assertThrows(IllegalArgumentException.class, () -> Merkle.revokedLeaf("0x" + "zz".repeat(20)));
        assertEquals("0x83c91d2020210e4924defde940dcb4e63ec3f20bbad4229da6019faba05cc206",
                Hex.encode0x(Merkle.revokedLeaf("0x86b2efd244acb31eb238a65ca05476ab42558071")));
    }
}
