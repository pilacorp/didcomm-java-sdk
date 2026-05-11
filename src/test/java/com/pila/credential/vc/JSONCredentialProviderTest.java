package com.pila.credential.vc;

import com.pila.credential.common.signer.DefaultSignerProvider;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JSONCredentialProviderTest {

    @Test
    void addProofByProvider_verifies_and_writes_proofValue_hex() throws Exception {
        String privKeyHex = "2c79686425aee8002cb189bf294f2d52ca43851797c7b6e78a7dc361c4373e46";
        String issuerDid = "did:example:issuer";
        String verificationMethod = issuerDid + "#key-1";
        String publicKeyHex = publicKeyFromPrivHex(privKeyHex);

        HttpServer server = startDidResolver(verificationMethod, publicKeyHex);
        try {
            CredentialConfig.init("http://127.0.0.1:" + server.getAddress().getPort());

            CredentialContents contents = new CredentialContents();
            contents.setIssuer(issuerDid);
            contents.setValidFrom(Instant.now());

            JSONCredential credential = JSONCredential.newJSONCredential(contents);
            credential.addProofByProvider(new DefaultSignerProvider(privKeyHex));

            Object proofObj = credential.getCredentialData().get("proof");
            assertNotNull(proofObj);
            assertTrue(proofObj instanceof Map);

            @SuppressWarnings("unchecked")
            Map<String, Object> proofMap = (Map<String, Object>) proofObj;

            Object proofValue = proofMap.get("proofValue");
            assertTrue(proofValue instanceof String);
            assertEquals(128, ((String) proofValue).length());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void addProofByProvider_rolls_back_proof_on_verify_failure() throws Exception {
        String privKeyHex = "2c79686425aee8002cb189bf294f2d52ca43851797c7b6e78a7dc361c4373e46";
        String issuerDid = "did:example:issuer";
        String verificationMethod = issuerDid + "#key-1";

        String wrongPublicKeyHex = publicKeyFromPrivHex("1".repeat(64));

        HttpServer server = startDidResolver(verificationMethod, wrongPublicKeyHex);
        try {
            CredentialConfig.init("http://127.0.0.1:" + server.getAddress().getPort());

            CredentialContents contents = new CredentialContents();
            contents.setIssuer(issuerDid);
            contents.setValidFrom(Instant.now());

            JSONCredential credential = JSONCredential.newJSONCredential(contents);

            assertThrows(Exception.class, () -> credential.addProofByProvider(new DefaultSignerProvider(privKeyHex)));
            assertNull(credential.getCredentialData().get("proof"));
        } finally {
            server.stop(0);
        }
    }

    private static HttpServer startDidResolver(String verificationMethodId, String publicKeyHex) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> handleDidResolve(exchange, verificationMethodId, publicKeyHex));
        server.setExecutor(Executors.newSingleThreadExecutor());
        server.start();
        return server;
    }

    private static void handleDidResolve(HttpExchange exchange, String verificationMethodId, String publicKeyHex)
            throws IOException {
        String body = "{"
                + "\"id\":\"did:example:issuer\","
                + "\"verificationMethod\":[{"
                + "\"id\":\"" + verificationMethodId + "\","
                + "\"publicKeyHex\":\"" + publicKeyHex + "\""
                + "}]"
                + "}";

        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static String publicKeyFromPrivHex(String privKeyHex) {
        String hex = privKeyHex.startsWith("0x") ? privKeyHex.substring(2) : privKeyHex;
        byte[] privBytes = Hex.decode(hex);
        ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECPoint q = spec.getG().multiply(new java.math.BigInteger(1, privBytes)).normalize();
        return Hex.toHexString(q.getEncoded(false));
    }
}

