package com.pila.credential.vccontract;

/** eth_call target; {@link JsonRpcClient} implements it. */
public interface CallSource {
    /** Returns the 0x-hex return data of calling {@code to} with calldata {@code dataHex} (0x-hex). */
    String call(String to, String dataHex);
}
