package com.pila.credential.didv2.subdid;

import com.pila.credential.common.verificationmethod.DIDDocument;
import com.pila.credential.didv2.Hex;
import com.pila.credential.didv2.Issuer;
import com.pila.credential.didv2.didcontract.ChainClient;
import com.pila.credential.didv2.didcontract.Contract;
import com.pila.credential.didv2.didcontract.WriterAnchor;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Verifies a Sub-DID against the chain that anchored it (Go subdid.Verifier): chain id, receipt, writer anchor,
 * Merkle path, revoked leaf and the writer's role. Safe for concurrent use; makes no network call at construction.
 */
public final class Verifier {
    private static final String STATUS_ACTIVATED = "activated";
    private static final String STATUS_DEACTIVATED = "deactivated";
    private static final Pattern HASH32 = Pattern.compile("0x[0-9a-f]{64}");

    public enum Reason {
        RESPONSE_MISMATCH("response_mismatch"),
        ID_MISMATCH("id_mismatch"),
        CONSENT_INVALID("consent_invalid"),
        NO_ANCHOR("no_anchor"),
        ROOT_MISMATCH("root_mismatch"),
        WRITER_REVOKED("writer_revoked"),
        PROOF_MISMATCH("proof_mismatch");

        public final String code;

        Reason(String code) {
            this.code = code;
        }
    }

    public enum Status {
        INVALID,
        ACTIVE,
        REVOKED
    }

    /** One configured chain: catalog code (e.g. "did"), EVM chain id, DIDRegistry 2.1 address, node access. */
    public record Chain(String code, long evmChainId, String didRegistry, ChainClient client) {
    }

    public static final class VerifyRequest {
        public String subDID;
        /** Optional: without it only a revoked leaf can be proven. */
        public DIDDocument document;
        public ProofResponse proof;
        public String chain;
    }

    public static final class Result {
        public final Status status;
        /** Null for ACTIVE and REVOKED. */
        public final Reason reason;
        public final String chain;
        public final String txHash;

        Result(Status status, Reason reason, String chain, String txHash) {
            this.status = status;
            this.reason = reason;
            this.chain = chain;
            this.txHash = txHash;
        }
    }

    private final Map<String, Chain> chains = new HashMap<>();

    public Verifier(Chain... configured) {
        if (configured == null || configured.length == 0) {
            throw new IllegalArgumentException("subdid: a verifier needs at least one chain");
        }
        for (Chain c : configured) {
            if (c.code() == null || c.code().isEmpty()) {
                throw new IllegalArgumentException("subdid: chain code is empty");
            }
            if (c.evmChainId() <= 0) {
                throw new IllegalArgumentException("subdid: chain " + c.code() + ": EVM chain id must be positive");
            }
            if (!Issuer.isAddress(c.didRegistry()) || Hex.normalize(c.didRegistry()).matches("0+")) {
                throw new IllegalArgumentException("subdid: chain " + c.code() + ": DID registry address is zero");
            }
            if (c.client() == null) {
                throw new IllegalArgumentException("subdid: chain " + c.code() + ": client is nil");
            }
            if (chains.put(c.code(), c) != null) {
                throw new IllegalArgumentException("subdid: chain " + c.code() + " is configured twice");
            }
        }
    }

    /**
     * Returns an INVALID result with a reason for a proof that does not hold, and throws {@link SubDIDException}
     * (never INVALID) when the chain cannot be read. A proof fetched before a revoke still verifies; one from a
     * since-removed writer reads WRITER_REVOKED.
     */
    public Result verifySubDID(VerifyRequest req) throws Exception {
        if (req.proof == null) {
            throw new SubDIDException(SubDIDException.Kind.INVALID_REQUEST, "subdid: proof is nil");
        }
        try {
            SubDIDDocuments.checkDID(req.subDID);
        } catch (Exception e) {
            throw new SubDIDException(SubDIDException.Kind.INVALID_REQUEST, "subdid: Sub-DID: " + e.getMessage(), e);
        }
        Chain c = chains.get(req.chain);
        if (c == null) {
            throw new SubDIDException(SubDIDException.Kind.INVALID_REQUEST,
                    "subdid: chain \"" + req.chain + "\" is not configured");
        }

        ProofResponse proof = req.proof;
        if (!consistentProof(proof, req.subDID)) {
            return invalid(c, Reason.RESPONSE_MISMATCH);
        }

        ProofResponse.ChainProof entry = chainEntry(proof, c.code());
        ParsedChainProof anchor = parseChainProof(entry);
        if (anchor == null) {
            return invalid(c, Reason.RESPONSE_MISMATCH);
        }

        byte[] leaf;
        Status verdict = Status.ACTIVE;
        String status = entry.status == null ? "" : entry.status;
        if (STATUS_ACTIVATED.equals(status)) {
            if (req.document == null) {
                throw new SubDIDException(SubDIDException.Kind.DOCUMENT_REQUIRED,
                        "subdid: an activated Sub-DID needs its document");
            }
            if (!req.subDID.equals(req.document.getId()) || !validates(req.document, proof.rootDid)) {
                return invalid(c, Reason.ID_MISMATCH);
            }
            try {
                SubDIDSignatures.verifyRootConsent(req.document, proof.rootDid);
            } catch (Exception e) {
                return invalid(c, Reason.CONSENT_INVALID);
            }
            leaf = SubDIDDocuments.docHashBytes(req.document);
        } else if (STATUS_DEACTIVATED.equals(status)) {
            leaf = Merkle.revokedLeaf(SubDIDDocuments.didAddress(req.subDID));
            verdict = Status.REVOKED;
        } else {
            return invalid(c, Reason.RESPONSE_MISMATCH);
        }

        Reason reason = checkOnChain(c, proof, anchor, leaf);
        if (reason != null) {
            return invalid(c, reason);
        }
        return new Result(verdict, null, c.code(), anchor.txHash);
    }

    private static Result invalid(Chain c, Reason reason) {
        return new Result(Status.INVALID, reason, c.code(), null);
    }

    private static boolean validates(DIDDocument doc, String rootDid) {
        try {
            SubDIDDocuments.validateSubDID(doc, rootDid);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean consistentProof(ProofResponse proof, String subDID) {
        if (!subDID.equals(proof.did) || !isDid(proof.rootDid)
                || !SubDIDDocuments.didPrefix(proof.rootDid).equals(SubDIDDocuments.didPrefix(subDID))
                || proof.rootDid.equals(subDID)) {
            return false;
        }
        String ti = proof.treeIndex == null ? "" : proof.treeIndex;
        return HASH32.matcher(ti).matches() || (ti.isEmpty() && (proof.chains == null || proof.chains.isEmpty()));
    }

    private static boolean isDid(String s) {
        try {
            SubDIDDocuments.checkDID(s);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static ProofResponse.ChainProof chainEntry(ProofResponse proof, String code) throws SubDIDException {
        if (proof.chains != null) {
            for (ProofResponse.ChainProof e : proof.chains) {
                if (code.equals(e.chain)) {
                    return e;
                }
            }
        }
        throw new SubDIDException(SubDIDException.Kind.NOT_ANCHORED,
                "subdid: the chain has not anchored this Sub-DID yet: chain " + code);
    }

    private record ParsedChainProof(String txHash, byte[] root, List<byte[]> path) {
    }

    private static ParsedChainProof parseChainProof(ProofResponse.ChainProof entry) {
        byte[] root = parseHash32(entry.root);
        if (!HASH32.matcher(entry.txHash == null ? "" : entry.txHash).matches() || root == null) {
            return null;
        }
        List<byte[]> path = new ArrayList<>();
        if (entry.path != null) {
            for (String s : entry.path) {
                byte[] p = parseHash32(s);
                if (p == null) {
                    return null;
                }
                path.add(p);
            }
        }
        return new ParsedChainProof(entry.txHash, root, path);
    }

    private static byte[] parseHash32(String s) {
        if (s == null || !HASH32.matcher(s).matches()) {
            return null;
        }
        return Hex.decodeGo(s);
    }

    private Reason checkOnChain(Chain c, ProofResponse proof, ParsedChainProof anchor, byte[] leaf)
            throws SubDIDException {
        if (!Merkle.verifyProof(leaf, anchor.path(), anchor.root())) {
            return Reason.PROOF_MISMATCH;
        }
        BigInteger chainId;
        try {
            chainId = c.client().chainId();
        } catch (Exception e) {
            throw new SubDIDException(SubDIDException.Kind.CHAIN_UNAVAILABLE,
                    "subdid: the chain could not be read: chain " + c.code() + ": " + e.getMessage(), e);
        }
        if (chainId == null || !chainId.equals(BigInteger.valueOf(c.evmChainId()))) {
            throw new SubDIDException(SubDIDException.Kind.CHAIN_MISMATCH,
                    "subdid: the chain could not be read: subdid: node reports another chain id: chain " + c.code()
                            + ": node reports " + chainId + ", want " + c.evmChainId());
        }
        Contract.Receipt receipt;
        try {
            receipt = c.client().transactionReceipt(anchor.txHash());
        } catch (Exception e) {
            throw new SubDIDException(SubDIDException.Kind.CHAIN_UNAVAILABLE,
                    "subdid: the chain could not be read: chain " + c.code() + ": receipt " + anchor.txHash() + ": "
                            + e.getMessage(), e);
        }
        if (receipt == null) {
            throw new SubDIDException(SubDIDException.Kind.CHAIN_UNAVAILABLE,
                    "subdid: the chain could not be read: chain " + c.code() + ": receipt " + anchor.txHash()
                            + " is empty");
        }
        if (receipt.status != 1) {
            return Reason.NO_ANCHOR;
        }
        WriterAnchor written = lastWriterAnchor(receipt, c.didRegistry(), proof);
        if (written == null) {
            return Reason.NO_ANCHOR;
        }
        if (!written.root.equalsIgnoreCase(Hex.encode0x(anchor.root()))) {
            return Reason.ROOT_MISMATCH;
        }
        boolean isWriter;
        try {
            isWriter = Contract.hasRole(c.client(), c.didRegistry(), Contract.SUBTREE_WRITER_ROLE, written.writer);
        } catch (Exception e) {
            throw new SubDIDException(SubDIDException.Kind.CHAIN_UNAVAILABLE,
                    "subdid: the chain could not be read: chain " + c.code() + ": " + e.getMessage(), e);
        }
        return isWriter ? null : Reason.WRITER_REVOKED;
    }

    private static WriterAnchor lastWriterAnchor(Contract.Receipt receipt, String registry, ProofResponse proof) {
        List<WriterAnchor> anchors;
        try {
            anchors = Contract.decodeWriterAnchors(receipt.logs, registry);
        } catch (Exception e) {
            return null;
        }
        String rootAddress = SubDIDDocuments.didAddress(proof.rootDid).toLowerCase(Locale.ROOT);
        BigInteger treeIndex = new BigInteger(proof.treeIndex.substring(2), 16);
        for (int i = anchors.size() - 1; i >= 0; i--) {
            WriterAnchor a = anchors.get(i);
            if (a.did.equalsIgnoreCase(rootAddress) && a.treeIndex.equals(treeIndex)) {
                return a;
            }
        }
        return null;
    }
}
