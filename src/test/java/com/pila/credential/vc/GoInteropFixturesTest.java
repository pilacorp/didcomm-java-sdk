package com.pila.credential.vc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.jsonmap.JSONMap;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Cross-language vectors from go-credential-sdk tests (legacy_hex_test, secp256k1 #89).
 */
public class GoInteropFixturesTest {

    private static final String LEGACY_HEX_VC = """
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

    private static final String LEGACY_PUB =
            "04e962c45627a43f3bec0af18c6c780ddbacceb8275b5204d494bc2cc44dc96d9805e64ee5ffeb6d05ed37284636c7cf6bfbaaa0d131f950cecc43110ac5510cad";

    @Test
    void legacyHexRdfcCredential_verifiesLikeGo() throws Exception {
        HttpServer server = startDidResolver(
                "did:example:legacy-issuer",
                "did:example:legacy-issuer#key-1",
                LEGACY_PUB);
        try {
            CredentialConfig.init("http://127.0.0.1:" + server.getAddress().getPort());
            ObjectMapper mapper = new ObjectMapper();
            JSONMap map = mapper.readValue(LEGACY_HEX_VC, JSONMap.class);
            assertTrue(map.verifyProof(CredentialConfig.getBaseURL()));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void secp256k1ProofCarryingItsOwnKey_isRefusedLikeGo() throws Exception {
        String body = """
                {
                  "@context": ["https://www.w3.org/2018/credentials/v1"],
                  "id": "urn:uuid:legacy-hex-001",
                  "type": ["VerifiableCredential"],
                  "issuer": "did:example:secp-suite-legacy",
                  "credentialSubject": {"id": "did:example:subject"},
                  "proof": {
                    "type": "EcdsaSecp256k1Signature2019",
                    "created": "2026-01-01T00:00:00Z",
                    "proofPurpose": "assertionMethod",
                    "verificationMethod": "deadbeef",
                    "proofValue": "00"
                  }
                }
                """;
        HttpServer server = startDidResolver(
                "did:example:secp-suite-legacy",
                "did:example:secp-suite-legacy#key-1",
                LEGACY_PUB);
        try {
            CredentialConfig.init("http://127.0.0.1:" + server.getAddress().getPort());
            ObjectMapper mapper = new ObjectMapper();
            JSONMap map = mapper.readValue(body, JSONMap.class);
            Exception ex = assertThrows(Exception.class, () -> map.verifyProof(CredentialConfig.getBaseURL()));
            assertTrue(ex.getMessage().contains("is not a DID URL") || ex.getMessage().contains("malformed detached JWS"));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void getSigningInput_returns32ByteDocumentDigest() throws Exception {
        CredentialContents contents = new CredentialContents();
        contents.setIssuer("did:example:issuer");
        JSONCredential cred = JSONCredential.newJSONCredential(contents);
        byte[] input = cred.getSigningInput();
        org.junit.jupiter.api.Assertions.assertEquals(32, input.length);
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
}
