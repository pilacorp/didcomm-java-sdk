package com.pila.credential.vp;

import com.pila.credential.common.signer.DefaultSignerProvider;
import com.pila.credential.vc.CredentialConfig;
import com.pila.credential.vc.CredentialContents;
import com.pila.credential.vc.JSONCredential;
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
import java.util.Map;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JSONPresentationTest {

    @Test
    void sign_and_verify_minimal_presentation() throws Exception {
        String privKeyHex = "2c79686425aee8002cb189bf294f2d52ca43851797c7b6e78a7dc361c4373e46";
        String holderDid = "did:example:holder";
        String verificationMethod = holderDid + "#key-1";
        String publicKeyHex = publicKeyFromPrivHex(privKeyHex);

        HttpServer server = startDidResolver(verificationMethod, publicKeyHex);
        try {
            CredentialConfig.init("http://127.0.0.1:" + server.getAddress().getPort());

            CredentialContents vcContents = new CredentialContents();
            vcContents.setIssuer(holderDid);
            vcContents.setSubject(java.util.List.of(new com.pila.credential.vc.Subject("did:example:subject", new java.util.HashMap<>())));
            vcContents.setContext(java.util.List.of("https://www.w3.org/ns/credentials/v2"));
            vcContents.setTypes(java.util.List.of("VerifiableCredential"));
            vcContents.setValidFrom(Instant.now());
            JSONCredential vc = JSONCredential.newJSONCredential(vcContents);
            vc.addProofByProvider(new DefaultSignerProvider(privKeyHex));

            PresentationContents vpc = new PresentationContents();
            vpc.setContext(List.of("https://www.w3.org/ns/credentials/v2"));
            vpc.setTypes(List.of("VerifiablePresentation"));
            vpc.setHolder(holderDid);
            vpc.setVerifiableCredentials(List.of(vc));

            JSONPresentation pres = JSONPresentation.create(vpc);
            pres.addProofByProvider(new DefaultSignerProvider(privKeyHex));
            pres.verify();

            Map<String, Object> out = pres.serialize();
            assertNotNull(out.get("proof"));
            assertTrue(out.containsKey("verifiableCredential"));

            byte[] raw = pres.getContents();
            JSONPresentation parsed = JSONPresentation.parse(raw);
            parsed.verify();

            JSONPresentation bound = JSONPresentation.create(vpc);
            bound.addProofByProvider(new DefaultSignerProvider(privKeyHex),
                    new PresentationOptions().withChallenge("n1").withDomain("https://verifier.example"));
            bound.verify(new PresentationOptions()
                    .withExpectedChallenge("n1")
                    .withExpectedDomain("https://verifier.example"));
            org.junit.jupiter.api.Assertions.assertThrows(Exception.class,
                    () -> bound.verify(new PresentationOptions().withExpectedChallenge("wrong")));
            // JSON-LD always appends to the proof set (Go): a second signature is a second proof, and
            // withReplaceProof is refused rather than silently appending.
            org.junit.jupiter.api.Assertions.assertThrows(Exception.class,
                    () -> bound.addProofByProvider(new DefaultSignerProvider(privKeyHex),
                            new PresentationOptions().withReplaceProof()));
            bound.addProofByProvider(new DefaultSignerProvider(privKeyHex));
            org.junit.jupiter.api.Assertions.assertEquals(2, ((java.util.List<?>) bound.serialize().get("proof")).size());
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
                + "\"id\":\"did:example:holder\","
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
