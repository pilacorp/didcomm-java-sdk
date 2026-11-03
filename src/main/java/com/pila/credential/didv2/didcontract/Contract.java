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

    public Contract(String rpcUrl, String contractAddress, long chainId) {
        this(rpcUrl, contractAddress, chainId, DEFAULT_GAS_LIMIT, BigInteger.ZERO);
    }

    public Contract(String rpcUrl, String contractAddress, long chainId, long gasLimit, BigInteger gasPrice) {
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
    }

    public LegacyTx.Signed createDIDTx(String issuerAddress, int didType, String docHash, String capId,
            Issuer.IssuerSignature issuerSig, long nonce, Signer txSigner) throws Exception {
        if (txSigner == null) {
            throw new Exception("tx signer is required");
        }
        validateSig(issuerSig);
        List<byte[]> words = List.of(
                Abi.addressWord(issuerAddress),
                Abi.uintWord(didType),
                Abi.bytes32Word(docHash),
                Abi.bytes32Word(capId),
                Abi.uintWord(issuerSig.v.intValue()),
                Abi.uintWord(issuerSig.r),
                Abi.uintWord(issuerSig.s));
        byte[] data = Abi.encodeHeadTail(CREATE_DID_SELECTOR, words);
        return LegacyTx.sign(contractAddress, data, nonce, gasLimit, gasPrice, chainId, txSigner);
    }

    public LegacyTx.Signed setDocumentHashTx(String didAddress, String docHash, String capId,
            Issuer.IssuerSignature issuerSig, long nonce, Signer txSigner) throws Exception {
        if (txSigner == null) {
            throw new Exception("tx signer is required");
        }
        validateSig(issuerSig);
        List<byte[]> words = List.of(
                Abi.addressWord(didAddress),
                Abi.bytes32Word(docHash),
                Abi.bytes32Word(capId),
                Abi.uintWord(issuerSig.v.intValue()),
                Abi.uintWord(issuerSig.r),
                Abi.uintWord(issuerSig.s));
        byte[] data = Abi.encodeHeadTail(SET_HASH_SELECTOR, words);
        return LegacyTx.sign(contractAddress, data, nonce, gasLimit, gasPrice, chainId, txSigner);
    }

    public LegacyTx.Signed setDocumentHashByIssuerTx(String didAddress, String docHash, long nonce, Signer txSigner)
            throws Exception {
        if (txSigner == null) {
            throw new Exception("tx signer is required");
        }
        byte[] data = Abi.encodeHeadTail(SET_HASH_BY_ISSUER_SELECTOR,
                List.of(Abi.addressWord(didAddress), Abi.bytes32Word(docHash)));
        return LegacyTx.sign(contractAddress, data, nonce, gasLimit, gasPrice, chainId, txSigner);
    }

    public static byte[] hasRoleCalldata(String role, String account) {
        return Abi.encodeHeadTail(HAS_ROLE_SELECTOR, List.of(Abi.bytes32Word(role), Abi.addressWord(account)));
    }

    public static boolean decodeHasRole(byte[] out) throws Exception {
        if (out == null || out.length != 32) {
            throw new Exception("didcontract: hasRole returned " + (out == null ? 0 : out.length) + " bytes, want 32");
        }
        return !new BigInteger(1, out).equals(BigInteger.ZERO);
    }

    public static List<WriterAnchor> decodeWriterAnchors(List<ReceiptLog> logs, String registry) throws Exception {
        if (logs == null) {
            throw new Exception("didcontract: receipt is nil");
        }
        if (registry == null || Hex.normalize(registry).equals("0000000000000000000000000000000000000000")) {
            throw new Exception("didcontract: registry address is zero");
        }
        String registryAddr = "0x" + Hex.normalize(registry);
        List<WriterAnchor> anchors = new ArrayList<>();
        for (ReceiptLog log : logs) {
            if (log == null) {
                continue;
            }
            if (!registryAddr.equalsIgnoreCase(log.address)) {
                continue;
            }
            if (log.topics == null || log.topics.isEmpty() || !WRITER_ANCHOR_TOPIC0.equalsIgnoreCase(log.topics.get(0))) {
                continue;
            }
            if (log.topics.size() != 2) {
                throw new Exception("BatchSubtreesAnchoredByWriter has " + log.topics.size() + " topics, want 2");
            }
            anchors.addAll(Abi.decodeWriterLog(log.topics.get(1), Hex.decode(log.data)));
        }
        return anchors;
    }

    private static void validateSig(Issuer.IssuerSignature sig) throws Exception {
        if (sig == null || sig.v == null || sig.r == null || sig.s == null) {
            throw new Exception("issuer signature V, R, S are required");
        }
    }

    public static final class ReceiptLog {
        public String address;
        public List<String> topics;
        public String data;
    }
}
