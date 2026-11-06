package com.pila.credential.vccontract;

import java.util.List;

/** Reads transaction receipts. Exists so log-filtering rules can be tested against synthetic receipts. */
public interface ReceiptSource {
    /**
     * Throws {@link VcContractException.TxNotFound} when the chain has no receipt (unknown or unmined).
     * Returning null is a source bug and is reported as an error, never as "not found".
     */
    TxReceipt getTransactionReceipt(String txHash);

    final class TxReceipt {
        /** 1 = success; anything else counts as reverted. */
        public final long status;
        /** May contain nulls (a JSON null from the node); they are skipped. */
        public final List<Log> logs;

        public TxReceipt(long status, List<Log> logs) {
            this.status = status;
            this.logs = logs == null ? List.of() : logs;
        }
    }

    final class Log {
        public final String address;
        public final List<String> topics;
        /** 0x-hex data section. */
        public final String data;

        public Log(String address, List<String> topics, String data) {
            this.address = address;
            this.topics = topics == null ? List.of() : topics;
            this.data = data == null ? "0x" : data;
        }
    }
}
