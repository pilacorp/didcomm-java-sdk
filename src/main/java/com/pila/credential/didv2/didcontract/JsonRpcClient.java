package com.pila.credential.didv2.didcontract;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.pila.credential.didv2.Hex;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/** A minimal Ethereum JSON-RPC client over {@code java.net.http} with an injectable {@link RpcTransport}. */
public final class JsonRpcClient implements ChainClient {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

    private final String url;
    private final RpcTransport transport;
    private final AtomicLong ids = new AtomicLong();

    public JsonRpcClient(String url) {
        this(url, JsonRpcClient::httpPost);
    }

    public JsonRpcClient(String url, RpcTransport transport) {
        if (transport == null) {
            throw new IllegalArgumentException("transport is nil");
        }
        this.url = url;
        this.transport = transport;
    }

    private static String httpPost(String url, String body) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(30))
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body)).build();
        HttpResponse<String> resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() / 100 != 2) {
            throw new Exception("rpc: HTTP " + resp.statusCode());
        }
        return resp.body();
    }

    /** One JSON-RPC call; returns {@code result} (a JSON null result is returned as a null node). */
    public JsonNode call(String method, Object... params) throws Exception {
        if (url == null || url.isEmpty()) {
            throw new Exception("RPC client is not initialized, please check RPC URL and try again");
        }
        ObjectNode req = MAPPER.createObjectNode();
        req.put("jsonrpc", "2.0");
        req.put("id", ids.incrementAndGet());
        req.put("method", method);
        ArrayNode arr = req.putArray("params");
        for (Object p : params) {
            arr.add(MAPPER.valueToTree(p));
        }
        JsonNode resp = MAPPER.readTree(transport.post(url, MAPPER.writeValueAsString(req)));
        if (resp == null || !resp.isObject()) {
            throw new Exception("rpc: malformed response");
        }
        JsonNode err = resp.get("error");
        if (err != null && !err.isNull()) {
            throw new Exception("rpc: " + err.path("message").asText(err.toString()));
        }
        JsonNode result = resp.get("result");
        return result == null ? MAPPER.nullNode() : result;
    }

    private static BigInteger quantity(JsonNode n, String what) throws Exception {
        if (n == null || !n.isTextual() || !n.asText().startsWith("0x") || n.asText().length() < 3) {
            throw new Exception("rpc: " + what + " is not a hex quantity");
        }
        return new BigInteger(n.asText().substring(2), 16);
    }

    @Override
    public BigInteger chainId() throws Exception {
        return quantity(call("eth_chainId"), "eth_chainId result");
    }

    @Override
    public BigInteger pendingNonceAt(String address) throws Exception {
        return quantity(call("eth_getTransactionCount", address, "pending"), "eth_getTransactionCount result");
    }

    @Override
    public byte[] callContract(String to, byte[] data) throws Exception {
        ObjectNode msg = MAPPER.createObjectNode();
        msg.put("to", to);
        msg.put("data", Hex.encode0x(data));
        JsonNode r = call("eth_call", msg, "latest");
        if (!r.isTextual() || !r.asText().startsWith("0x")) {
            throw new Exception("rpc: eth_call result is not hex data");
        }
        return Hex.decodeGo(r.asText());
    }

    @Override
    public Contract.Receipt transactionReceipt(String txHash) throws Exception {
        JsonNode r = call("eth_getTransactionReceipt", txHash);
        if (r.isNull()) {
            throw new Exception("not found");
        }
        Contract.Receipt out = new Contract.Receipt();
        out.status = r.has("status") ? quantity(r.get("status"), "receipt status").longValueExact() : 0;
        out.logs = new ArrayList<>();
        for (JsonNode l : r.path("logs")) {
            Contract.ReceiptLog log = new Contract.ReceiptLog();
            log.address = l.path("address").asText();
            log.data = l.path("data").asText("0x");
            List<String> topics = new ArrayList<>();
            for (JsonNode t : l.path("topics")) {
                topics.add(t.asText());
            }
            log.topics = topics;
            out.logs.add(log);
        }
        return out;
    }
}
