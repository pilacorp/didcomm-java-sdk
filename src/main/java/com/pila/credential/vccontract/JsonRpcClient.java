package com.pila.credential.vccontract;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Default network implementation: eth_getTransactionReceipt and eth_call over java.net.http JSON-RPC. */
public final class JsonRpcClient implements ReceiptSource, CallSource {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final HttpClient http = HttpClient.newHttpClient();
    private final URI uri;

    public JsonRpcClient(String rpcUrl) {
        if (rpcUrl == null || rpcUrl.isEmpty()) {
            throw new IllegalArgumentException("RPC URL is required");
        }
        this.uri = URI.create(rpcUrl);
    }

    private JsonNode rpc(String method, List<Object> params) {
        try {
            String body = JSON.writeValueAsString(Map.of("jsonrpc", "2.0", "id", 1, "method", method, "params", params));
            HttpResponse<String> res = http.send(HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(30))
                    .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                    HttpResponse.BodyHandlers.ofString());
            if (res.statusCode() / 100 != 2) {
                throw new VcContractException(method + ": HTTP " + res.statusCode());
            }
            JsonNode root = JSON.readTree(res.body());
            if (root.hasNonNull("error")) {
                throw new VcContractException(method + ": " + root.get("error"));
            }
            return root.path("result");
        } catch (IOException e) {
            throw new VcContractException(method + " failed: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new VcContractException(method + " interrupted", e);
        }
    }

    @Override
    public TxReceipt getTransactionReceipt(String txHash) {
        JsonNode r = rpc("eth_getTransactionReceipt", List.of(txHash));
        if (r.isNull() || r.isMissingNode()) {
            throw new VcContractException.TxNotFound();
        }
        String status = r.path("status").asText("0x0");
        long st = status.startsWith("0x") && status.length() > 2 ? Long.parseLong(status.substring(2), 16) : 0;
        List<Log> logs = new ArrayList<>();
        for (JsonNode l : r.path("logs")) {
            if (l.isNull()) {
                logs.add(null);
                continue;
            }
            List<String> topics = new ArrayList<>();
            l.path("topics").forEach(t -> topics.add(t.asText()));
            logs.add(new Log(l.path("address").asText(), topics, l.path("data").asText("0x")));
        }
        return new TxReceipt(st, logs);
    }

    @Override
    public String call(String to, String dataHex) {
        return rpc("eth_call", List.of(Map.of("to", to, "data", dataHex), "latest")).asText("0x");
    }
}
