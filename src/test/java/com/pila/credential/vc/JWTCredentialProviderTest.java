package com.pila.credential.vc;

import com.pila.credential.common.dto.Proof;
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
import java.util.Base64;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class JWTCredentialProviderTest {

    @Test
    void addProofByProvider_verifies_and_creates_64_byte_jwt_signature() throws Exception {
        String privKeyHex = "2c79686425aee8002cb189bf294f2d52ca43851797c7b6e78a7dc361c4373e46";
        String issuerDid = "did:example:issuer";
        String kid = issuerDid + "#key-1";
        String publicKeyHex = publicKeyFromPrivHex(privKeyHex);

        HttpServer server = startDidResolver(kid, publicKeyHex);
        try {
            CredentialConfig.init("http://127.0.0.1:" + server.getAddress().getPort());

            CredentialContents contents = new CredentialContents();
            contents.setIssuer(issuerDid);
            contents.setValidFrom(Instant.now());

            JWTCredential credential = JWTCredential.newJWTCredential(contents);
            credential.addProofByProvider(new DefaultSignerProvider(privKeyHex));

            String jwt = (String) credential.serialize();
            String[] parts = jwt.split("\\.");
            assertEquals(3, parts.length);

            byte[] signatureBytes = Base64.getUrlDecoder().decode(parts[2]);
            assertEquals(64, signatureBytes.length);
        } finally {
            server.stop(0);
        }
    }

    @Test
    void addProofByProvider_rolls_back_signature_on_verify_failure() throws Exception {
        String privKeyHex = "2c79686425aee8002cb189bf294f2d52ca43851797c7b6e78a7dc361c4373e46";
        String issuerDid = "did:example:issuer";
        String kid = issuerDid + "#key-1";

        // Serve a mismatched public key so verify-after-sign fails.
        String wrongPublicKeyHex = publicKeyFromPrivHex("1".repeat(64));

        HttpServer server = startDidResolver(kid, wrongPublicKeyHex);
        try {
            CredentialConfig.init("http://127.0.0.1:" + server.getAddress().getPort());

            CredentialContents contents = new CredentialContents();
            contents.setIssuer(issuerDid);
            contents.setValidFrom(Instant.now());

            JWTCredential credential = JWTCredential.newJWTCredential(contents);

            assertThrows(Exception.class, () -> credential.addProofByProvider(new DefaultSignerProvider(privKeyHex)));

            // Rollback: unsigned JWT should remain (header.payload only).
            String jwt = (String) credential.serialize();
            assertEquals(2, jwt.split("\\.").length);
        } finally {
            server.stop(0);
        }
    }

    @Test
    void addCustomProof_accepts_65_byte_signature_and_normalizes() throws Exception {
        CredentialContents contents = new CredentialContents();
        contents.setIssuer("did:example:issuer");
        contents.setValidFrom(Instant.now());

        JWTCredential credential = JWTCredential.newJWTCredential(contents);

        byte[] sig65 = new byte[65];
        for (int i = 0; i < 65; i++) {
            sig65[i] = (byte) (100 + i);
        }

        Proof proof = new Proof();
        proof.setSignature(sig65);
        credential.addCustomProof(proof);

        String jwt = (String) credential.serialize();
        String[] parts = jwt.split("\\.");
        assertEquals(3, parts.length);

        byte[] signatureBytes = Base64.getUrlDecoder().decode(parts[2]);
        assertEquals(64, signatureBytes.length);
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

