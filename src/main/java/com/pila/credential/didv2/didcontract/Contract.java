package com.pila.credential.didv2.didcontract;

import com.pila.credential.didv2.Hex;
import com.pila.credential.didv2.Issuer;
import com.pila.credential.didv2.Keccak256;
import com.pila.credential.didv2.Signer;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class Contract {
    public static final long DEFAULT_GAS_LIMIT = 200000L;
    public static final String SUBTREE_WRITER_ROLE = Keccak256.hashHex(
            "SUBTREE_WRITER_ROLE".getBytes(StandardCharsets.UTF_8));
    public static final String WRITER_ANCHOR_TOPIC0 = Keccak256.hashHex(
            "BatchSubtreesAnchoredByWriter(address,address[],uint256[],bytes32[])"
                    .getBytes(StandardCharsets.UTF_8));
    public static final byte[] GET_CAPABILITY_EPOCH_SELECTOR = Abi.selector("getCapabilityEpoch(address)");
    public static final byte[] HAS_ROLE_SELECTOR = Abi.selector("hasRole(bytes32,address)");
    public static final byte[] CREATE_DID_SELECTOR = Abi.selector(
            "createDID(address,uint8,bytes32,bytes32,uint8,bytes32,bytes32)");
    public static final byte[] SET_HASH_SELECTOR = Abi.selector(
            "setDocumentHash(address,bytes32,bytes32,uint8,bytes32,bytes32)");
    public static final byte[] SET_HASH_BY_ISSUER_SELECTOR = Abi.selector(
            "setDocumentHashByIssuer(address,bytes32)");

    public final String rpcUrl;
    public final String contractAddress;
    public final long chainId;
    public final long gasLimit;
    public final BigInteger gasPrice;
    private final ChainClient client;

    public Contract(String rpcUrl, String contractAddress, long chainId) {
        this(rpcUrl, contractAddress, chainId, DEFAULT_GAS_LIMIT, BigInteger.ZERO);
    }

    public Contract(String rpcUrl, String contractAddress, long chainId, long gasLimit, BigInteger gasPrice) {
        this(rpcUrl, contractAddress, chainId, gasLimit, gasPrice,
                rpcUrl == null || rpcUrl.isEmpty() ? null : new JsonRpcClient(rpcUrl));
    }

    /** {@code client} may be null: read operations (epoch, nonce) then fail, transaction building still works. */
    public Contract(String rpcUrl, String contractAddress, long chainId, long gasLimit, BigInteger gasPrice,
            ChainClient client) {
        if (!Issuer.isAddress(contractAddress)) {
            throw new IllegalArgumentException("contract address is required");
        }
        if (chainId <= 0) {
            throw new IllegalArgumentException("chain ID must be greater than 0, it's required");
        }
        this.rpcUrl = rpcUrl;
        this.contractAddress = contractAddress.toLowerCase(Locale.ROOT);
        this.chainId = chainId;
        this.gasLimit = gasLimit > 0 ? gasLimit : DEFAULT_GAS_LIMIT;
        this.gasPrice = gasPrice == null ? BigInteger.ZERO : gasPrice;
        this.client = client;
    }

    /** Go GetCapabilityEpoch: getCapabilityEpoch(address) of the registry for an issuer. */
    public long getCapabilityEpoch(String signerAddr) throws Exception {
        if (signerAddr == null || signerAddr.isEmpty()) {
            throw new Exception("signer address is required");
        }
        if (client == null) {
            throw new Exception("RPC client is not initialized, please check RPC URL and try again");
        }
        byte[] out;
        try {
            out = client.callContract(contractAddress,
                    Abi.encodeHeadTail(GET_CAPABILITY_EPOCH_SELECTOR, List.of(Abi.addressWord(signerAddr))));
        } catch (Exception e) {
            throw new Exception("contract call failed: " + e.getMessage(), e);
        }
        if (out == null || out.length == 0) {
            throw new Exception("contract returned no data");
        }
        if (out.length < 32) {
            throw new Exception("abi: cannot unmarshal: length insufficient " + out.length + " require 32");
        }
        BigInteger epoch = new BigInteger(1, java.util.Arrays.copyOfRange(out, 0, 32));
        if (epoch.bitLength() > 64) {
            throw new Exception("abi: improperly encoded uint64 value");
        }
        return epoch.longValue();
    }

    /** Go GetNonce: the pending transaction count of an address. */
    public long getNonce(String address) throws Exception {
        if (client == null) {
            throw new Exception("RPC client is not initialized, please check RPC URL and try again");
        }
        BigInteger n;
        try {
            n = client.pendingNonceAt(address);
        } catch (Exception e) {
            throw new Exception("failed to get nonce: " + e.getMessage(), e);
        }
        if (n.bitLength() > 64) {
            throw new Exception("failed to get nonce: value does not fit uint64");
        }
        return n.longValue();
    }

    /** Go didcontract.HasRole: hasRole(role, account) on the registry, the answer must be a canonical bool. */
    public static boolean hasRole(ChainClient caller, String registry, String role, String account)
            throws Exception {
        byte[] out;
        try {
            out = caller.callContract(registry, hasRoleCalldata(role, account));
        } catch (Exception e) {
            throw new Exception("didcontract: call hasRole: " + e.getMessage(), e);
        }
        return decodeHasRole(out);
    }

    /** eth_chainId / receipt access for verifiers. */
    public ChainClient client() {
        return client;
    }

    public static final class Receipt {
        public long status;
        public List<ReceiptLog> logs;
    }

    public LegacyTx.Signed createDIDTx(CreateDIDRequest req, Signer txSigner) throws Exception {
        if (txSigner == null) {
            throw new Exception("tx signer is required");
        }
        if (req == null) {
            throw new Exception("CreateDIDRequest is required");
        }
        try {
            req.validate();
        } catch (Exception e) {
            throw new Exception("invalid request: " + e.getMessage(), e);
        }
        List<byte[]> words = List.of(
                Abi.addressWord(req.issuerAddress),
                Abi.uintWord(req.didType),
                Abi.bytes32Word(req.docHash),
                Abi.bytes32Word(req.capId),
                Abi.uintWord(req.issuerSig.v.intValue()),
                Abi.uintWord(req.issuerSig.r),
                Abi.uintWord(req.issuerSig.s));
        byte[] data = Abi.encodeHeadTail(CREATE_DID_SELECTOR, words);
        return LegacyTx.sign(contractAddress, data, req.nonce, gasLimit, gasPrice, chainId, txSigner);
    }

    public LegacyTx.Signed createDIDTx(String issuerAddress, int didType, String docHash, String capId,
            Issuer.IssuerSignature issuerSig, long nonce, Signer txSigner) throws Exception {
        CreateDIDRequest r = new CreateDIDRequest();
        r.issuerAddress = issuerAddress;
        r.didType = didType;
        r.docHash = docHash;
        r.capId = capId;
        r.issuerSig = issuerSig;
        r.nonce = nonce;
        return createDIDTx(r, txSigner);
    }

    public LegacyTx.Signed setDocumentHashTx(SetDocumentHashRequest req, Signer txSigner) throws Exception {
        if (txSigner == null) {
            throw new Exception("tx signer is required");
        }
        if (req == null) {
            throw new Exception("SetDocumentHashRequest is required");
        }
        try {
            req.validate();
        } catch (Exception e) {
            throw new Exception("invalid request: " + e.getMessage(), e);
        }
        List<byte[]> words = List.of(
                Abi.addressWord(req.didAddress),
                Abi.bytes32Word(req.docHash),
                Abi.bytes32Word(req.capId),
                Abi.uintWord(req.issuerSig.v.intValue()),
                Abi.uintWord(req.issuerSig.r),
                Abi.uintWord(req.issuerSig.s));
        byte[] data = Abi.encodeHeadTail(SET_HASH_SELECTOR, words);
        return LegacyTx.sign(contractAddress, data, req.nonce, gasLimit, gasPrice, chainId, txSigner);
    }

    public LegacyTx.Signed setDocumentHashTx(String didAddress, String docHash, String capId,
            Issuer.IssuerSignature issuerSig, long nonce, Signer txSigner) throws Exception {
        SetDocumentHashRequest r = new SetDocumentHashRequest();
        r.didAddress = didAddress;
        r.docHash = docHash;
        r.capId = capId;
        r.issuerSig = issuerSig;
        r.nonce = nonce;
        return setDocumentHashTx(r, txSigner);
    }

    public LegacyTx.Signed setDocumentHashByIssuerTx(SetDocumentHashByIssuerRequest req, Signer txSigner)
            throws Exception {
        if (txSigner == null) {
            throw new Exception("tx signer is required");
        }
        if (req == null) {
            throw new Exception("SetDocumentHashByIssuerRequest is required");
        }
        try {
            req.validate();
        } catch (Exception e) {
            throw new Exception("invalid request: " + e.getMessage(), e);
        }
        byte[] data = Abi.encodeHeadTail(SET_HASH_BY_ISSUER_SELECTOR,
                List.of(Abi.addressWord(req.didAddress), Abi.bytes32Word(req.docHash)));
        return LegacyTx.sign(contractAddress, data, req.nonce, gasLimit, gasPrice, chainId, txSigner);
    }

    public LegacyTx.Signed setDocumentHashByIssuerTx(String didAddress, String docHash, long nonce, Signer txSigner)
            throws Exception {
        SetDocumentHashByIssuerRequest r = new SetDocumentHashByIssuerRequest();
        r.didAddress = didAddress;
        r.docHash = docHash;
        r.nonce = nonce;
        return setDocumentHashByIssuerTx(r, txSigner);
    }

    public static byte[] hasRoleCalldata(String role, String account) {
        return Abi.encodeHeadTail(HAS_ROLE_SELECTOR, List.of(Abi.bytes32Word(role), Abi.addressWord(account)));
    }

    /** A 32-byte ABI bool: 0 or 1 (go-ethereum rejects any other word). */
    public static boolean decodeHasRole(byte[] out) throws Exception {
        if (out == null || out.length != 32) {
            throw new Exception("didcontract: hasRole returned " + (out == null ? 0 : out.length) + " bytes, want 32");
        }
        BigInteger v = new BigInteger(1, out);
        if (v.equals(BigInteger.ZERO)) {
            return false;
        }
        if (v.equals(BigInteger.ONE)) {
            return true;
        }
        throw new Exception("didcontract: unpack hasRole: abi: improperly encoded boolean value");
    }

    /** Go DecodeWriterAnchors: does not check the receipt status. */
    public static List<WriterAnchor> decodeWriterAnchors(List<ReceiptLog> logs, String registry) throws Exception {
        if (logs == null) {
            throw new Exception("didcontract: receipt is nil");
        }
        if (!Issuer.isAddress(registry) || Hex.normalize(registry).equals("0000000000000000000000000000000000000000")) {
            throw new Exception("didcontract: registry address is zero");
        }
        String registryAddr = Hex.normalize(registry);
        List<WriterAnchor> anchors = new ArrayList<>();
        int index = 0;
        for (ReceiptLog log : logs) {
            int logIndex = index++;
            if (log == null) {
                continue;
            }
            if (log.address == null || !registryAddr.equals(Hex.normalize(log.address))) {
                continue;
            }
            if (log.topics == null || log.topics.isEmpty() || !WRITER_ANCHOR_TOPIC0.equalsIgnoreCase(log.topics.get(0))) {
                continue;
            }
            try {
                if (log.topics.size() != 2) {
                    throw new Exception("BatchSubtreesAnchoredByWriter has " + log.topics.size() + " topics, want 2");
                }
                String writerTopic = log.topics.get(1);
                if (writerTopic == null || writerTopic.length() != 66 || !writerTopic.startsWith("0x")) {
                    throw new Exception("writer topic is not a 32-byte hash");
                }
                anchors.addAll(Abi.decodeWriterLog(writerTopic, Hex.decodeGo(log.data)));
            } catch (Exception e) {
                throw new Exception("didcontract: log " + logIndex + ": " + e.getMessage(), e);
            }
        }
        return anchors;
    }

    public static final class ReceiptLog {
        public String address;
        public List<String> topics;
        public String data;
    }
}
