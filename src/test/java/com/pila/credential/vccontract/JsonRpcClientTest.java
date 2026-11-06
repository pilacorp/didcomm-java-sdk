package com.pila.credential.vccontract;

import static com.pila.credential.vccontract.Fx.*;
import static org.junit.jupiter.api.Assertions.*;

import com.sun.net.httpserver.HttpServer;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** The default JSON-RPC implementation against a local JDK HttpServer (no network). */
class JsonRpcClientTest {
    HttpServer server;
    final AtomicReference<String> reply = new AtomicReference<>();
    final AtomicReference<String> seen = new AtomicReference<>();
    final AtomicReference<Integer> code = new AtomicReference<>(200);

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", ex -> {
            seen.set(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] out = reply.get().getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(code.get(), out.length);
            ex.getResponseBody().write(out);
            ex.close();
        });
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    JsonRpcClient client() {
        return new JsonRpcClient("http://127.0.0.1:" + server.getAddress().getPort());
    }

    @Test
    void readsReceiptAndFeedsTheRegistry() {
        String root = leaf(0xbb);
        reply.set("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"status\":\"0x1\",\"logs\":[null,{\"address\":\""
                + REGISTRY + "\",\"topics\":[\"" + topic("TreeRootAnchored") + "\",\"" + pad(ISSUER) + "\",\"" + root
                + "\"],\"data\":\"0x\"}]}}");
        CredentialRegistry r = CredentialRegistry.connect("http://127.0.0.1:" + server.getAddress().getPort(), "", REGISTRY);
        assertTrue(r.isRootAnchored(leaf(1), ISSUER, root));
        assertTrue(seen.get().contains("eth_getTransactionReceipt") && seen.get().contains(leaf(1)));
    }

    @Test
    void nullResultIsTxNotFoundAndRevertedStatusIsReported() {
        reply.set("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":null}");
        assertThrows(VcContractException.TxNotFound.class, () -> client().getTransactionReceipt(leaf(1)));
        reply.set("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"status\":\"0x0\",\"logs\":[]}}");
        assertEquals(0, client().getTransactionReceipt(leaf(1)).status);
    }

    @Test
    void ethCallAndErrors() {
        reply.set("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x01\"}");
        assertEquals("0x01", client().call(REGISTRY, "0x1234"));
        assertTrue(seen.get().contains("eth_call") && seen.get().contains("0x1234") && seen.get().contains("latest"));
        reply.set("{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32000,\"message\":\"boom\"}}");
        assertTrue(assertThrows(VcContractException.class, () -> client().call(REGISTRY, "0x")).getMessage().contains("boom"));
        code.set(500);
        assertThrows(VcContractException.class, () -> client().call(REGISTRY, "0x"));
        assertThrows(IllegalArgumentException.class, () -> new JsonRpcClient(""));
    }
}
