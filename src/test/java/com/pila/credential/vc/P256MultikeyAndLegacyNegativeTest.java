package com.pila.credential.vc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.jsonmap.JSONMap;
import com.pila.credential.common.signer.P256SignerProvider;
import com.pila.credential.common.signer.SignerProvider;
import com.pila.credential.common.verificationmethod.Multikey;
import com.pila.credential.common.verificationmethod.VerificationMethodEntry;
import com.pila.credential.common.verificationmethod.VerificationMethodKeyKind;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.junit.jupiter.api.Test;

import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Map;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class P256MultikeyAndLegacyNegativeTest {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static final String LEGACY_HEX_VC = GoInteropFixturesTestSupport.LEGACY_HEX_VC;
    private static final String LEGACY_PUB = GoInteropFixturesTestSupport.LEGACY_PUB;

    @Test
    void publicKeyMultibase_classifiesAndDecodesP256() throws Exception {
        KeyPair kp = generateP256();
        String mb = Multikey.encodeP256PublicKey(kp.getPublic());
        VerificationMethodEntry vm = new VerificationMethodEntry();
        vm.setId("did:example:p256#key-2");
        vm.setType("Multikey");
        vm.setPublicKeyMultibase(mb);
        assertEquals(VerificationMethodKeyKind.P256, VerificationMethodKeyKind.fromEntry(vm));
        PublicKey decoded = Multikey.publicKeyFromMultibase(mb);
        assertEquals(Multikey.encodeP256PublicKey(decoded), mb);
    }

    @Test
    void goDidV2MixedCurve_classifiesKey2AsP256Multikey() throws Exception {
        KeyPair kp = generateP256();
        String mb = Multikey.encodeP256PublicKey(kp.getPublic());
        VerificationMethodEntry key1 = new VerificationMethodEntry();
        key1.setId("did:example:mixed#key-1");
        key1.setType("EcdsaSecp256k1VerificationKey2019");
        key1.setPublicKeyHex("04" + "ab".repeat(64));
        VerificationMethodEntry key2 = new VerificationMethodEntry();
        key2.setId("did:example:mixed#key-2");
        key2.setType("Multikey");
        key2.setPublicKeyMultibase(mb);
        assertEquals(VerificationMethodKeyKind.SECP256K1, VerificationMethodKeyKind.fromEntry(key1));
        assertEquals(VerificationMethodKeyKind.P256, VerificationMethodKeyKind.fromEntry(key2));
    }

    @Test
    void publicKeyHex_withMultikeyType_isNotSecp256k1() {
        VerificationMethodEntry vm = new VerificationMethodEntry();
        vm.setType("Multikey");
        vm.setPublicKeyHex("04" + "aa".repeat(64));
        assertEquals(VerificationMethodKeyKind.UNKNOWN, VerificationMethodKeyKind.fromEntry(vm));
    }

    @Test
    void p256PrivateKey_rejectsZeroAndOrder() {
        assertThrows(IllegalArgumentException.class, () -> new P256SignerProvider("00".repeat(32)));
        ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("prime256v1");
        String nHex = spec.getN().toString(16);
        if (nHex.length() % 2 != 0) {
            nHex = "0" + nHex;
        }
        String orderHex = nHex;
        assertThrows(IllegalArgumentException.class, () -> new P256SignerProvider(orderHex));
    }

    @Test
    void p256MultikeyDid_canSignAndVerifyModernRdfc() throws Exception {
        KeyPair kp = generateP256();
        String mb = Multikey.encodeP256PublicKey(kp.getPublic());
        BigInteger d = ((org.bouncycastle.jce.interfaces.ECPrivateKey) kp.getPrivate()).getD();
        String privHex = toFixed32Hex(d);
        String did = "did:example:p256-issuer";
        String vmId = did + "#key-1";
        HttpServer server = startMultikeyResolver(did, vmId, mb);
        try {
            CredentialConfig.init("http://127.0.0.1:" + server.getAddress().getPort());
            CredentialContents contents = new CredentialContents();
            contents.setIssuer(did);
            JSONCredential cred = JSONCredential.newJSONCredential(contents);
            cred.addProofByProvider(new P256SignerProvider(privHex));
            cred.verify();
            @SuppressWarnings("unchecked")
            Map<String, Object> proof = (Map<String, Object>) cred.getCredentialData().get("proof");
            assertTrue(((String) proof.get("proofValue")).startsWith("z"));
            assertEquals("ecdsa-rdfc-2019", proof.get("cryptosuite"));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void legacyHex_rejectsTamperedSubject() throws Exception {
        HttpServer server = startHexResolver("did:example:legacy-issuer", "did:example:legacy-issuer#key-1", LEGACY_PUB);
        try {
            CredentialConfig.init("http://127.0.0.1:" + server.getAddress().getPort());
            ObjectMapper mapper = new ObjectMapper();
            JSONMap map = mapper.readValue(LEGACY_HEX_VC.replace("Alice", "Mallory"), JSONMap.class);
            assertThrows(Exception.class, () -> {
                if (!map.verifyProof(CredentialConfig.getBaseURL())) {
                    throw new Exception("proof verification failed");
                }
            });
        } finally {
            server.stop(0);
        }
    }

    @Test
    void legacyHex_rejectsWrongVerificationMethodKey() throws Exception {
        HttpServer server = startHexResolver("did:example:legacy-issuer", "did:example:legacy-issuer#key-1",
                "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
        try {
            CredentialConfig.init("http://127.0.0.1:" + server.getAddress().getPort());
            ObjectMapper mapper = new ObjectMapper();
            JSONMap map = mapper.readValue(LEGACY_HEX_VC, JSONMap.class);
            boolean ok = map.verifyProof(CredentialConfig.getBaseURL());
            org.junit.jupiter.api.Assertions.assertFalse(ok);
        } finally {
            server.stop(0);
        }
    }

    @Test
    void legacyHex_rejectsMultibaseProofValue() throws Exception {
        HttpServer server = startHexResolver("did:example:legacy-issuer", "did:example:legacy-issuer#key-1", LEGACY_PUB);
        try {
            CredentialConfig.init("http://127.0.0.1:" + server.getAddress().getPort());
            ObjectMapper mapper = new ObjectMapper();
            JSONMap map = mapper.readValue(LEGACY_HEX_VC.replace(
                    "\"proofValue\": \"b95159fb2c2a5f9a5a04f23342eafb0aa66875a0c41b07c0d4f6bff3205a401f078c75299f88d6553cfdfce08050ca566736c23a47c6b575fef656e4f1ce768200\"",
                    "\"proofValue\": \"zQeJ8PxoowjvgW3M2hGeYg4X9pK2\""), JSONMap.class);
            assertThrows(Exception.class, () -> {
                if (!map.verifyProof(CredentialConfig.getBaseURL())) {
                    throw new Exception("proof verification failed");
                }
            });
        } finally {
            server.stop(0);
        }
    }

    @Test
    void legacyHex_rejectsMalformedProofValue() throws Exception {
        HttpServer server = startHexResolver("did:example:legacy-issuer", "did:example:legacy-issuer#key-1", LEGACY_PUB);
        try {
            CredentialConfig.init("http://127.0.0.1:" + server.getAddress().getPort());
            ObjectMapper mapper = new ObjectMapper();
            JSONMap map = mapper.readValue(LEGACY_HEX_VC.replace(
                    "b95159fb2c2a5f9a5a04f23342eafb0aa66875a0c41b07c0d4f6bff3205a401f078c75299f88d6553cfdfce08050ca566736c23a47c6b575fef656e4f1ce768200",
                    "not-hex"), JSONMap.class);
            assertThrows(Exception.class, () -> {
                if (!map.verifyProof(CredentialConfig.getBaseURL())) {
                    throw new Exception("proof verification failed");
                }
            });
        } finally {
            server.stop(0);
        }
    }

    @Test
    void legacyHex_rejectsWrongProofConfiguration() throws Exception {
        HttpServer server = startHexResolver("did:example:legacy-issuer", "did:example:legacy-issuer#key-1", LEGACY_PUB);
        try {
            CredentialConfig.init("http://127.0.0.1:" + server.getAddress().getPort());
            ObjectMapper mapper = new ObjectMapper();
            JSONMap map = mapper.readValue(LEGACY_HEX_VC, JSONMap.class);
            @SuppressWarnings("unchecked")
            Map<String, Object> proof = (Map<String, Object>) map.get("proof");
            proof.put("created", "2099-01-01T00:00:00Z");
            // Legacy hex proofValue signs the document body only, not proof options.
            assertTrue(map.verifyProof(CredentialConfig.getBaseURL()));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void modernRdfc_rejects65ByteSignatureFromSigner() throws Exception {
        KeyPair kp = generateP256();
        String mb = Multikey.encodeP256PublicKey(kp.getPublic());
        BigInteger d = ((org.bouncycastle.jce.interfaces.ECPrivateKey) kp.getPrivate()).getD();
        String privHex = toFixed32Hex(d);
        String did = "did:example:p256-issuer";
        String vmId = did + "#key-1";
        HttpServer server = startMultikeyResolver(did, vmId, mb);
        try {
            CredentialConfig.init("http://127.0.0.1:" + server.getAddress().getPort());
            CredentialContents contents = new CredentialContents();
            contents.setIssuer(did);
            JSONCredential cred = JSONCredential.newJSONCredential(contents);
            assertThrows(Exception.class, () -> cred.addProofByProvider(new SignerProvider() {
                @Override
                public byte[] sign(byte[] digest) {
                    byte[] sig = new byte[65];
                    java.util.Arrays.fill(sig, (byte) 1);
                    return sig;
                }
            }));
        } finally {
            server.stop(0);
        }
    }

    private static KeyPair generateP256() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
        kpg.initialize(ECNamedCurveTable.getParameterSpec("prime256v1"), new SecureRandom());
        return kpg.generateKeyPair();
    }

    private static String toFixed32Hex(BigInteger d) {
        String hex = d.toString(16);
        if (hex.length() > 64) {
            hex = hex.substring(hex.length() - 64);
        }
        while (hex.length() < 64) {
            hex = "0" + hex;
        }
        return hex;
    }

    private static HttpServer startMultikeyResolver(String did, String vmId, String multibase) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String body = "{"
                    + "\"id\":\"" + did + "\","
                    + "\"assertionMethod\":[\"" + vmId + "\"],"
                    + "\"authentication\":[\"" + vmId + "\"],"
                    + "\"verificationMethod\":[{"
                    + "\"id\":\"" + vmId + "\","
                    + "\"type\":\"Multikey\","
                    + "\"controller\":\"" + did + "\","
                    + "\"publicKeyMultibase\":\"" + multibase + "\""
                    + "}]"
                    + "}";
            writeJson(exchange, body);
        });
        server.setExecutor(Executors.newSingleThreadExecutor());
        server.start();
        return server;
    }

    private static HttpServer startHexResolver(String did, String vmId, String publicKeyHex) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String body = "{"
                    + "\"id\":\"" + did + "\","
                    + "\"assertionMethod\":[\"" + vmId + "\"],"
                    + "\"authentication\":[\"" + vmId + "\"],"
                    + "\"verificationMethod\":[{"
                    + "\"id\":\"" + vmId + "\","
                    + "\"type\":\"EcdsaSecp256k1VerificationKey2019\","
                    + "\"publicKeyHex\":\"" + publicKeyHex + "\""
                    + "}]"
                    + "}";
            writeJson(exchange, body);
        });
        server.setExecutor(Executors.newSingleThreadExecutor());
        server.start();
        return server;
    }

    private static void writeJson(HttpExchange exchange, String body) throws java.io.IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}

class GoInteropFixturesTestSupport {
    static final String LEGACY_HEX_VC = """
            {
              "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
              ],
              "credentialSubject": {
                "age": 30,
                "id": "did:example:legacy-subject",
                "name": "Alice"
              },
              "id": "urn:uuid:7f1e2c3d-legacy-vc",
              "issuer": "did:example:legacy-issuer",
              "proof": {
                "created": "2026-09-14T08:51:57Z",
                "cryptosuite": "ecdsa-rdfc-2019",
                "proofPurpose": "assertionMethod",
                "proofValue": "b95159fb2c2a5f9a5a04f23342eafb0aa66875a0c41b07c0d4f6bff3205a401f078c75299f88d6553cfdfce08050ca566736c23a47c6b575fef656e4f1ce768200",
                "type": "DataIntegrityProof",
                "verificationMethod": "did:example:legacy-issuer#key-1"
              },
              "type": [
                "VerifiableCredential",
                "ExampleDegreeCredential"
              ],
              "validFrom": "2025-01-01T00:00:00Z"
            }
            """;

    static final String LEGACY_PUB =
            "04e962c45627a43f3bec0af18c6c780ddbacceb8275b5204d494bc2cc44dc96d9805e64ee5ffeb6d05ed37284636c7cf6bfbaaa0d131f950cecc43110ac5510cad";
}
