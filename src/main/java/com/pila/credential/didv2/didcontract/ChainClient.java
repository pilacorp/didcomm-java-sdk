package com.pila.credential.didv2.didcontract;

import java.math.BigInteger;

/**
 * Read access to a chain node (the part of Go's {@code *ethclient.Client} the SDK uses). {@link JsonRpcClient}
 * implements it over JSON-RPC.
 */
public interface ChainClient {
    /** eth_chainId. */
    BigInteger chainId() throws Exception;

    /** eth_getTransactionReceipt; throws when the node has no receipt for the hash. */
    Contract.Receipt transactionReceipt(String txHash) throws Exception;

    /** eth_call at the latest block. */
    byte[] callContract(String to, byte[] data) throws Exception;

    /** eth_getTransactionCount at the pending block (Go PendingNonceAt). */
    BigInteger pendingNonceAt(String address) throws Exception;
}
