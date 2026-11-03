package com.pila.credential.vp;

import com.pila.credential.common.signer.DefaultSignerProvider;
import com.pila.credential.vc.CredentialConfig;
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
import java.util.List;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class JWTPresentationTest {

    @Test
    void createSignVerify() throws Exception {
        String priv = "2c79686425aee8002cb189bf294f2d52ca43851797c7b6e78a7dc361c4373e46";
        String holder = "did:example:holder";
        String kid = holder + "#key-1";
        String pub = publicKeyFromPrivHex(priv);

        HttpServer server = startDidResolver(holder, kid, pub);
        try {
            CredentialConfig.init("http://127.0.0.1:" + server.getAddress().getPort());

            PresentationContents pc = new PresentationContents();
            pc.setContext(List.of("https://www.w3.org/ns/credentials/v2"));
            pc.setTypes(List.of("VerifiablePresentation"));
            pc.setHolder(holder);
            pc.setValidFrom(Instant.now());

            JWTPresentation pres = JWTPresentation.create(pc,
                    new PresentationOptions().withChallenge("n1").withDomain("https://verifier.example"));
            pres.addProofByProvider(new DefaultSignerProvider(priv));
            assertDoesNotThrow(() -> pres.verify());
            assertDoesNotThrow(() -> pres.verify(new PresentationOptions()
                    .withExpectedChallenge("n1")
                    .withExpectedDomain("https://verifier.example")));
            org.junit.jupiter.api.Assertions.assertThrows(Exception.class,
                    () -> pres.verify(new PresentationOptions().withExpectedDomain("https://other.example")));
        } finally {
            server.stop(0);
        }
    }

    private static HttpServer startDidResolver(String did, String verificationMethodId, String publicKeyHex)
            throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> handleDidResolve(exchange, did, verificationMethodId, publicKeyHex));
        server.setExecutor(Executors.newSingleThreadExecutor());
        server.start();
        return server;
    }

    private static void handleDidResolve(HttpExchange exchange, String did, String verificationMethodId,
            String publicKeyHex) throws IOException {
        String body = "{"
                + "\"id\":\"" + did + "\","
                + "\"assertionMethod\":[\"" + verificationMethodId + "\"],"
                + "\"authentication\":[\"" + verificationMethodId + "\"],"
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
