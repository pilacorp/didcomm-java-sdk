package com.pila.credential.didv2.didcontract;

/** Posts one JSON-RPC request body to {@code url} and returns the response body (injectable in tests). */
@FunctionalInterface
public interface RpcTransport {
    String post(String url, String jsonBody) throws Exception;
}
