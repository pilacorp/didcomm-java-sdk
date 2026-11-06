package com.pila.credential.vccontract;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.didv2.Hex;
import com.pila.credential.didv2.Keccak256;
import com.pila.credential.didv2.didcontract.Abi;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Read-only client for the Credential Registry contract (receipt logs and eth_call); needs no key and no gas.
 *
 * <p>Reading a root from a log means trusting the emitter, and anyone can deploy a contract emitting these
 * event signatures, so only logs from the trusted addresses are believed. <b>An empty trusted set (no
 * contractAddress, no alsoTrust) believes every emitter</b> and verifies nothing meaningful: name at least one
 * address in anything that accepts a credential from outside.
 *
 * <p>contractAddress is both the eth_call target (deprecated view functions only) and a trusted emitter;
 * alsoTrust addresses are only trusted, never called.
 */
public final class CredentialRegistry {
    // The five shapes an anchoring has ever taken: three current, two legacy (still valid on chain).
    static final String BATCH_ANCHORED = "BatchRootsAnchored";
    static final String SINGLE_ANCHORED = "TreeRootAnchored";
    static final String ISSUER_ANCHORED = "IssuerRootsAnchored";
    static final String LEGACY_BATCH = "BatchTreesUpdated";
    static final String LEGACY_SINGLE = "TreeUpdated";

    // Topic counts of a well-formed log (event id + indexed fields).
    private static final int SINGLE_TOPICS = 3;
    private static final int ISSUER_TOPICS = 2;
    private static final int LEGACY_SINGLE_TOPICS = 3;

    private static final String ZERO32 = "0x" + "00".repeat(32);

    /** Event name to its topic0 and non-indexed data types, derived from the embedded contract ABI. */
    static final Map<String, EventDef> EVENTS = loadEvents();

    static final class EventDef {
        final String topic;
        final List<String> dataTypes;

        EventDef(String topic, List<String> dataTypes) {
            this.topic = topic;
            this.dataTypes = dataTypes;
        }
    }

    private final ReceiptSource receipts;
    private final CallSource caller;
    /** eth_call target, null when no contractAddress was given. */
    private final String contract;
    /** Lowercase 0x addresses whose logs are believed; empty means every emitter (see trusts()). */
    private final Set<String> trusted = new HashSet<>();

    /**
     * @param receipts        where receipts come from (may be null: every log operation then fails)
     * @param caller          eth_call implementation for the deprecated view functions (may be null)
     * @param contractAddress "" or null when you only read logs
     * @param alsoTrust       further emitters to believe, never called
     */
    public CredentialRegistry(ReceiptSource receipts, CallSource caller, String contractAddress,
            String... alsoTrust) {
        this.receipts = receipts;
        this.caller = caller;
        if (contractAddress != null && !contractAddress.isEmpty()) {
            try {
                contract = parseContractAddress(contractAddress);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("invalid contract address: " + e.getMessage(), e);
            }
            trusted.add(contract);
        } else {
            contract = null;
        }
        for (int i = 0; i < alsoTrust.length; i++) {
            try {
                trusted.add(parseContractAddress(alsoTrust[i]));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(
                        "invalid contract address in alsoTrust at index " + i + ": " + e.getMessage(), e);
            }
        }
    }

    /** Wires receipts and calls to a JSON-RPC node ({@link JsonRpcClient}); rpcUrl is required. */
    public static CredentialRegistry connect(String rpcUrl, String contractAddress, String... alsoTrust) {
        JsonRpcClient rpc = new JsonRpcClient(rpcUrl);
        return new CredentialRegistry(rpc, rpc, contractAddress, alsoTrust);
    }

    /** Rejects the zero address on top of the format check: it names no deployment and can only be a mistake. */
    private static String parseContractAddress(String value) {
        if (!Validation.isHexAddress(value)) {
            throw new IllegalArgumentException("\"" + value + "\" is not a 20-byte hex address");
        }
        String a = Validation.address(value);
        if (a.equals("0x" + "0".repeat(40))) {
            throw new IllegalArgumentException("the zero address names no deployment");
        }
        return a;
    }

    /** Whether logs emitted by address may be believed. An empty trusted set believes everyone. */
    public boolean trusts(String address) {
        return trusted.isEmpty() || trusted.contains(Validation.address(address));
    }

    // ---- verification ----

    /**
     * Folds the proof and checks the root against the anchoring in {@code req.txHash}'s receipt logs.
     * False means the chain was asked and does not attest the leaf (including a reverted tx); an exception
     * means the chain could not be asked (bad input, RPC failure, {@link VcContractException.TxNotFound}).
     * {@code req.treeIndex} is ignored: the contract no longer records one.
     */
    public boolean verifyVCHashByTx(VerifyByTxRequest req) {
        if (req == null) {
            throw new IllegalArgumentException("verify request is required");
        }
        req.validate();
        String[] lp = decodeLeafAndProof(req.leaf, req.proof);
        String root = foldProof(lp[0], Arrays.asList(lp).subList(1, lp.length));
        String txHash = hexToBytes32(req.txHash);
        try {
            if (req.contractAddress == null || req.contractAddress.isEmpty()) {
                return isRootAnchored(txHash, req.issuerAddress, root);
            }
            return isRootAnchoredAtContract(txHash, req.issuerAddress, root, req.contractAddress);
        } catch (VcContractException.TxReverted e) {
            return false; // ran and wrote nothing: a verdict, not a failure to check
        }
    }

    /**
     * Whether txHash records issuer anchoring root, across all five event shapes, from any trusted emitter.
     *
     * @throws VcContractException.TxNotFound no receipt; TxReverted the tx failed. A tx that simply lacks the
     *     root is false.
     */
    public boolean isRootAnchored(String txHash, String issuer, String root) {
        return rootAnchored(txHash, issuer, root, null);
    }

    /** {@link #isRootAnchored} restricted to one deployment, which must already be trusted (pins only narrow). */
    public boolean isRootAnchoredAtContract(String txHash, String issuer, String root, String contractAddress) {
        if (!trusts(contractAddress)) {
            throw new VcContractException.UntrustedContract(contractAddress);
        }
        return rootAnchored(txHash, issuer, root, Validation.address(contractAddress));
    }

    private boolean rootAnchored(String txHash, String issuerIn, String rootIn, String emitter) {
        if (receipts == null) {
            throw new IllegalStateException("registry is not initialized");
        }
        String issuer = Validation.address(issuerIn);
        String root = hexToBytes32(rootIn);
        // A zero root is a verdict, not a failure: the contract rejects an empty root, so none is ever logged.
        if (root.equals(ZERO32)) {
            return false;
        }
        for (ReceiptSource.Log log : successfulLogs(txHash)) {
            if (log == null) {
                continue; // a JSON null in the node's response
            }
            if (emitter != null ? !emitter.equals(Validation.address(log.address)) : !trusts(log.address)) {
                continue;
            }
            if (log.topics.isEmpty()) {
                continue;
            }
            if (logAnchors(log, issuer, root)) {
                return true;
            }
        }
        return false;
    }

    private List<ReceiptSource.Log> successfulLogs(String txHash) {
        ReceiptSource.TxReceipt receipt = receipts.getTransactionReceipt(txHash);
        if (receipt == null) {
            throw new VcContractException("receipt source returned no receipt and no error for tx " + txHash);
        }
        if (receipt.status != 1) {
            throw new VcContractException.TxReverted();
        }
        return receipt.logs;
    }

    /** Whether one log records issuer anchoring root. Legacy events match on (issuer, root); tree index is skipped. */
    private static boolean logAnchors(ReceiptSource.Log log, String issuer, String root) {
        List<String> t = new ArrayList<>();
        log.topics.forEach(x -> t.add(x.toLowerCase(Locale.ROOT)));
        if (t.stream().anyMatch(x -> x.length() != 66)) {
            return false; // not a 32-byte topic: cannot be one of ours
        }
        String id = t.get(0);
        if (id.equals(EVENTS.get(SINGLE_ANCHORED).topic)) {
            return t.size() == SINGLE_TOPICS && topicAddress(t.get(1)).equals(issuer) && t.get(2).equals(root);
        }
        if (id.equals(EVENTS.get(BATCH_ANCHORED).topic)) {
            Object[] d = decodeData(BATCH_ANCHORED, log.data);
            return d != null && pairPresent(strings(d[0]), strings(d[1]), issuer, root);
        }
        if (id.equals(EVENTS.get(ISSUER_ANCHORED).topic)) {
            if (t.size() != ISSUER_TOPICS || !topicAddress(t.get(1)).equals(issuer)) {
                return false;
            }
            Object[] d = decodeData(ISSUER_ANCHORED, log.data);
            return d != null && strings(d[0]).contains(root);
        }
        if (id.equals(EVENTS.get(LEGACY_SINGLE).topic)) {
            if (t.size() != LEGACY_SINGLE_TOPICS || !topicAddress(t.get(1)).equals(issuer)) {
                return false;
            }
            Object[] d = decodeData(LEGACY_SINGLE, log.data);
            return d != null && d[0].equals(root);
        }
        if (id.equals(EVENTS.get(LEGACY_BATCH).topic)) {
            Object[] d = decodeData(LEGACY_BATCH, log.data);
            return d != null && pairPresent(strings(d[0]), strings(d[2]), issuer, root);
        }
        return false;
    }

    /** An indexed address is left-padded into a 32-byte topic: the last 20 bytes. */
    private static String topicAddress(String topic) {
        return "0x" + topic.substring(topic.length() - 40);
    }

    /**
     * Mismatched parallel arrays fail closed: the contract reverts on them, so such a log is not an anchoring
     * this client can read, and answering from a prefix would trust part of a record known to be malformed.
     */
    private static boolean pairPresent(List<String> issuers, List<String> roots, String issuer, String root) {
        if (issuers.size() != roots.size()) {
            return false;
        }
        for (int i = 0; i < issuers.size(); i++) {
            if (issuers.get(i).equals(issuer) && roots.get(i).equals(root)) {
                return true;
            }
        }
        return false;
    }

    @SuppressWarnings("unchecked")
    private static List<String> strings(Object o) {
        return (List<String>) o;
    }

    // ---- deprecated readers ----

    /**
     * Root that txHash anchored for issuer and treeIndex, from the legacy BatchTreesUpdated logs only.
     *
     * @deprecated against the current contract this always throws RootNotAnchored; use {@link #isRootAnchored}.
     */
    @Deprecated
    public String getAnchoredRoot(String txHash, String issuer, long treeIndex) {
        if (receipts == null) {
            throw new IllegalStateException("registry is not initialized");
        }
        String want = Validation.address(issuer);
        BigInteger idx = unsigned(treeIndex);
        for (ReceiptSource.Log log : successfulLogs(txHash)) {
            if (log == null || !trusts(log.address) || log.topics.isEmpty()
                    || !log.topics.get(0).equalsIgnoreCase(EVENTS.get(LEGACY_BATCH).topic)) {
                continue;
            }
            Object[] d = decodeData(LEGACY_BATCH, log.data);
            if (d == null) {
                continue;
            }
            List<String> issuers = strings(d[0]);
            @SuppressWarnings("unchecked")
            List<BigInteger> indices = (List<BigInteger>) d[1];
            List<String> roots = strings(d[2]);
            if (issuers.size() != indices.size() || issuers.size() != roots.size()) {
                continue;
            }
            for (int i = 0; i < issuers.size(); i++) {
                if (issuers.get(i).equals(want) && indices.get(i).equals(idx)) {
                    return roots.get(i);
                }
            }
        }
        throw new VcContractException.RootNotAnchored();
    }

    /**
     * @deprecated the current contract has no verifyVC; use {@link #verifyVCHashByTx}. Works only against an
     *     older deployment that keeps roots in storage.
     */
    @Deprecated
    public boolean verifyVCHashOnChain(VerifyRequest req) {
        requireContract("verifyVC");
        if (req == null) {
            throw new IllegalArgumentException("verify request is required");
        }
        req.validate();
        String[] lp = decodeLeafAndProof(req.leaf, req.proof);
        byte[] out = ethCall(verifyVCCalldata(req.issuerAddress, req.treeIndex, lp[0],
                Arrays.asList(lp).subList(1, lp.length)), "verifyVC");
        return decodeBool(out, "verifyVC");
    }

    /** @deprecated the current contract has no getTreeRoot; ask {@link #isRootAnchored} about a root you hold. */
    @Deprecated
    public String getTreeRoot(String issuerAddress, long treeIndex) {
        requireContract("getTreeRoot");
        requireAddress(issuerAddress);
        byte[] out = ethCall(treeCalldata("getTreeRoot(address,uint256)", issuerAddress, treeIndex), "getTreeRoot");
        if (out.length != 32) {
            throw new VcContractException("getTreeRoot returned " + out.length + " bytes, want 32");
        }
        return Hex.encode0x(out);
    }

    /** @deprecated the current contract has no treeExists. */
    @Deprecated
    public boolean hasTree(String issuerAddress, long treeIndex) {
        requireContract("treeExists");
        requireAddress(issuerAddress);
        return decodeBool(ethCall(treeCalldata("treeExists(address,uint256)", issuerAddress, treeIndex), "treeExists"),
                "treeExists");
    }

    private void requireContract(String fn) {
        if (contract == null) {
            throw new VcContractException.NoContractAddress(fn
                    + " is a call on the contract that keeps roots in storage, so its address must be passed");
        }
    }

    private static void requireAddress(String a) {
        if (!Validation.isHexAddress(a)) {
            throw new IllegalArgumentException("invalid issuer address: \"" + a + "\"");
        }
    }

    private byte[] ethCall(byte[] calldata, String fn) {
        if (caller == null) {
            throw new IllegalStateException("registry is not initialized");
        }
        String res;
        try {
            res = caller.call(contract, Hex.encode0x(calldata));
        } catch (VcContractException e) {
            throw new VcContractException(fn + " call failed: " + e.getMessage(), e);
        }
        if (res == null || res.equals("0x") || res.isEmpty()) {
            throw new VcContractException(fn + " returned no data");
        }
        return Hex.decode(res);
    }

    private static boolean decodeBool(byte[] out, String fn) {
        if (out.length != 32) {
            throw new VcContractException(fn + " returned " + out.length + " bytes, want 32");
        }
        for (int i = 0; i < 31; i++) {
            if (out[i] != 0) {
                throw new VcContractException(fn + ": improperly encoded boolean value");
            }
        }
        if (out[31] > 1 || out[31] < 0) {
            throw new VcContractException(fn + ": improperly encoded boolean value");
        }
        return out[31] == 1;
    }

    // ---- calldata ----

    static byte[] verifyVCCalldata(String issuer, long treeIndex, String leaf, List<String> proof) {
        byte[] head = new byte[4 + 4 * 32];
        System.arraycopy(Abi.selector("verifyVC(address,uint256,bytes32,bytes32[])"), 0, head, 0, 4);
        System.arraycopy(Abi.addressWord(issuer), 0, head, 4, 32);
        System.arraycopy(Abi.uintWord(unsigned(treeIndex)), 0, head, 36, 32);
        System.arraycopy(Abi.bytes32Word(leaf), 0, head, 68, 32);
        System.arraycopy(Abi.uintWord(BigInteger.valueOf(128)), 0, head, 100, 32);
        byte[] out = Arrays.copyOf(head, head.length + 32 + proof.size() * 32);
        System.arraycopy(Abi.uintWord(BigInteger.valueOf(proof.size())), 0, out, head.length, 32);
        for (int i = 0; i < proof.size(); i++) {
            System.arraycopy(Abi.bytes32Word(proof.get(i)), 0, out, head.length + 32 + i * 32, 32);
        }
        return out;
    }

    static byte[] treeCalldata(String signature, String issuer, long treeIndex) {
        return Abi.encodeHeadTail(Abi.selector(signature),
                List.of(Abi.addressWord(issuer), Abi.uintWord(unsigned(treeIndex))));
    }

    private static BigInteger unsigned(long v) {
        return new BigInteger(Long.toUnsignedString(v));
    }

    // ---- hashing / proof folding ----

    /**
     * Folds a leaf with its sibling path into the root: sorted-pair keccak256, leaves not hashed, empty path
     * = the leaf itself. Fold a hash you computed from the credential: an inner node folds to the root too.
     * Inputs and output are 0x 32-byte hex.
     */
    public static String foldProof(String leaf, List<String> proof) {
        String computed = leaf.toLowerCase(Locale.ROOT);
        for (String sibling : proof) {
            computed = hashPair(computed, sibling);
        }
        return computed;
    }

    /** keccak256 of two 32-byte nodes concatenated in ascending byte order (the contract's pair hashing). */
    public static String hashPair(String a, String b) {
        byte[] x = Hex.decode(a);
        byte[] y = Hex.decode(b);
        return Arrays.compareUnsigned(x, y) < 0 ? Hex.encode0x(Keccak256.hash(x, y))
                : Hex.encode0x(Keccak256.hash(y, x));
    }

    /** Go hexToBytes32: optional lowercase "0x", exactly 32 bytes of hex; returns 0x-lowercase. */
    public static String hexToBytes32(String s) {
        String h = s == null ? "" : (s.startsWith("0x") ? s.substring(2) : s);
        if (h.length() % 2 != 0 || !Validation.isHex(h)) {
            throw new IllegalArgumentException("invalid hex: encoding/hex: invalid byte");
        }
        if (h.length() / 2 != 32) {
            throw new IllegalArgumentException("length must be 32 bytes, got " + h.length() / 2);
        }
        return "0x" + h.toLowerCase(Locale.ROOT);
    }

    public static List<String> parseProof(List<String> proof) {
        List<String> out = new ArrayList<>();
        for (int i = 0; i < (proof == null ? 0 : proof.size()); i++) {
            try {
                out.add(hexToBytes32(proof.get(i)));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("proof element " + i + ": " + e.getMessage());
            }
        }
        return out;
    }

    /** Returns [leaf, proof...] normalised. */
    private static String[] decodeLeafAndProof(String leafHex, List<String> proofHex) {
        String leaf;
        try {
            leaf = hexToBytes32(leafHex);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("invalid leaf: " + e.getMessage());
        }
        List<String> all = new ArrayList<>();
        all.add(leaf);
        all.addAll(parseProof(proofHex));
        return all.toArray(new String[0]);
    }

    // ---- ABI event data decoding ----

    /**
     * Decodes the non-indexed data section for an event: address[] / bytes32[] as lowercase hex string lists,
     * uint256[] as BigInteger lists, bytes32 as a hex string. Null when the data is malformed (fail closed).
     */
    static Object[] decodeData(String event, String dataHex) {
        try {
            byte[] data = Hex.decode(dataHex);
            List<String> types = EVENTS.get(event).dataTypes;
            Object[] out = new Object[types.size()];
            for (int i = 0; i < types.size(); i++) {
                if (data.length < (i + 1) * 32) {
                    return null;
                }
                byte[] word = Arrays.copyOfRange(data, i * 32, (i + 1) * 32);
                String type = types.get(i);
                if (type.equals("bytes32")) {
                    out[i] = Hex.encode0x(word);
                    continue;
                }
                BigInteger off = new BigInteger(1, word);
                if (off.bitLength() > 31 || off.longValue() + 32 > data.length) {
                    return null;
                }
                int o = off.intValue();
                BigInteger n = new BigInteger(1, Arrays.copyOfRange(data, o, o + 32));
                if (n.bitLength() > 31 || o + 32L + n.longValue() * 32 > data.length) {
                    return null;
                }
                int len = n.intValue();
                List<Object> items = new ArrayList<>(len);
                for (int j = 0; j < len; j++) {
                    byte[] w = Arrays.copyOfRange(data, o + 32 + j * 32, o + 64 + j * 32);
                    switch (type) {
                        case "address[]" -> items.add(Hex.encode0x(Arrays.copyOfRange(w, 12, 32)));
                        case "bytes32[]" -> items.add(Hex.encode0x(w));
                        case "uint256[]" -> items.add(new BigInteger(1, w));
                        default -> throw new IllegalStateException("unsupported ABI type " + type);
                    }
                }
                out[i] = items;
            }
            return out;
        } catch (IllegalArgumentException | IndexOutOfBoundsException e) {
            return null;
        }
    }

    private static Map<String, EventDef> loadEvents() {
        try (InputStream in = CredentialRegistry.class.getResourceAsStream("credential_registry_smc_abi.json")) {
            Map<String, EventDef> events = new HashMap<>();
            for (JsonNode e : new ObjectMapper().readTree(in)) {
                if (!"event".equals(e.path("type").asText())) {
                    continue;
                }
                List<String> sig = new ArrayList<>();
                List<String> dataTypes = new ArrayList<>();
                for (JsonNode input : e.get("inputs")) {
                    sig.add(input.get("type").asText());
                    if (!input.path("indexed").asBoolean()) {
                        dataTypes.add(input.get("type").asText());
                    }
                }
                String name = e.get("name").asText();
                String signature = name + "(" + String.join(",", sig) + ")";
                events.put(name, new EventDef(Keccak256.hashHex(signature.getBytes(StandardCharsets.UTF_8)),
                        dataTypes));
            }
            return events;
        } catch (IOException | RuntimeException e) {
            throw new ExceptionInInitializerError(e);
        }
    }
}
