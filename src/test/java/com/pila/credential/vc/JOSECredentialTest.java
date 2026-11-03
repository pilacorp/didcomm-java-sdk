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
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;

public class JOSECredentialTest {

    @Test
    void create_sign_verify_vcJwt_flat_payload() throws Exception {
        String privKeyHex = "2c79686425aee8002cb189bf294f2d52ca43851797c7b6e78a7dc361c4373e46";
        String issuerDid = "did:example:issuer";
        String kid = issuerDid + "#key-1";
        String publicKeyHex = publicKeyFromPrivHex(privKeyHex);

        HttpServer server = startDidResolver(kid, publicKeyHex);
        try {
            CredentialConfig.init("http://127.0.0.1:" + server.getAddress().getPort());

            CredentialContents contents = new CredentialContents();
            contents.setContext(List.of("https://www.w3.org/ns/credentials/v2"));
            contents.setTypes(List.of("VerifiableCredential"));
            contents.setIssuer(issuerDid);
            contents.setValidFrom(Instant.now());
            Subject subject = new Subject();
            subject.setId("did:example:subject");
            contents.setSubject(List.of(subject));

            JOSECredential credential = JOSECredential.create(contents);
            credential.addProofByProvider(new DefaultSignerProvider(privKeyHex));

            String token = (String) credential.serialize();
            String[] parts = token.split("\\.");
            assertEquals(3, parts.length);

            @SuppressWarnings("unchecked")
            Map<String, Object> header = decodeJsonPart(parts[0]);
            assertEquals(JOSECredential.TYPE_VC_JWT, header.get("typ"));

            @SuppressWarnings("unchecked")
            Map<String, Object> payload = decodeJsonPart(parts[1]);
            assertNull(payload.get("vc"));
            assertEquals(issuerDid, payload.get("issuer"));

            credential.verify();

            Credential parsed = CredentialParser.parseCredential(token.getBytes(StandardCharsets.UTF_8));
            assertInstanceOf(JOSECredential.class, parsed);
            assertEquals("JOSE", parsed.getType());
            parsed.verify();

            JOSECredential viaOpts = JOSECredential.create(contents,
                    new CredentialOptions().withVerificationMethodKey("key-1"));
            viaOpts.addProofByProvider(new DefaultSignerProvider(privKeyHex));
            viaOpts.verify();
            org.junit.jupiter.api.Assertions.assertThrows(Exception.class, () -> viaOpts.present(List.of()));
        } finally {
            server.stop(0);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> decodeJsonPart(String encoded) throws Exception {
        byte[] bytes = Base64.getUrlDecoder().decode(encoded);
        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        return mapper.readValue(bytes, Map.class);
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
