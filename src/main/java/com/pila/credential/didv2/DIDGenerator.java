package com.pila.credential.didv2;

import com.pila.credential.common.verificationmethod.DIDDocument;
import com.pila.credential.didv2.didcontract.Contract;
import com.pila.credential.didv2.didcontract.LegacyTx;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

public final class DIDGenerator {
    private final Config baseConfig;
    private final Contract didContract;

    @SafeVarargs
    public DIDGenerator(Consumer<Config>... options) {
        this.baseConfig = Config.apply(options);
        this.didContract = baseConfig.contract();
    }

    public static final class DIDTxResult {
        public String did;
        public DIDDocument document;
        public LegacyTx.Signed transaction;
        public String secretPrivateKeyHex;
        /** The generated private key (Go DIDTxResult.Secret); null unless produced by {@code generateDID}. */
        public Secret secret;
    }

    @SafeVarargs
    public final DIDTxResult generateDID(int didType, String hash, Map<String, Object> metadata,
            Consumer<Config>... options) throws Exception {
        Config cfg = resolve(options);
        KeyPair keyPair = Documents.generateDualCurveDIDKeyPair();
        List<Consumer<Config>> opts = new ArrayList<>(List.of(options));
        opts.add(c -> c.didSigner = new DefaultProvider(keyPair.privateKeyHex));
        if (cfg.enableP256VM && keyPair.p256X != null) {
            String didAddr = Documents.addressFromPublicKeyHex(keyPair.publicKeyHex);
            var p256VM = Documents.newP256MultikeyVM(Types.toDID(cfg.method, didAddr), "#key-2", keyPair.p256X,
                    keyPair.p256Y);
            opts.add(c -> c.extraVMs.add(new Documents.VmSpec(p256VM, null)));
        }
        DIDTxResult didTx = generateDIDTX(didType, keyPair.publicKeyHex, hash, metadata,
                opts.toArray(Consumer[]::new));
        didTx.secretPrivateKeyHex = keyPair.privateKeyHex;
        didTx.secret = new Secret(keyPair.privateKeyHex);
        return didTx;
    }

    @SafeVarargs
    public final DIDTxResult generateDID(DIDType didType, String hash, Map<String, Object> metadata,
            Consumer<Config>... options) throws Exception {
        return generateDID(didType.value, hash, metadata, options);
    }

    @SafeVarargs
    public final DIDTxResult generateDIDTX(DIDType didType, String didPublicKeyHex, String hash,
            Map<String, Object> metadata, Consumer<Config>... options) throws Exception {
        return generateDIDTX(didType.value, didPublicKeyHex, hash, metadata, options);
    }

    @SafeVarargs
    public final DIDTxResult generateDIDTX(int didType, String didPublicKeyHex, String hash,
            Map<String, Object> metadata, Consumer<Config>... options) throws Exception {
        Config cfg = resolve(options);
        if (cfg.issuerSigner == null) {
            throw new Exception("issuer signer is required");
        }
        String issuerAddr = cfg.issuerSigner.getAddress();
        String didAddr = Documents.addressFromPublicKeyHex(didPublicKeyHex);
        Issuer.IssuerSignature issuerSig = generateIssuerSignature(didType, didAddr, issuerAddr,
                Config.withDIDConfig(cfg));
        String issuerDID = Types.toDID(cfg.method, issuerAddr);
        String didIdentifier = Types.toDID(cfg.method, didAddr);
        DIDDocument didDoc = Documents.generateDIDDocument(didPublicKeyHex, didIdentifier, hash, issuerDID, didType,
                metadata, cfg.extraVMs);
        Documents.validateDIDDocument(didDoc);
        String docHash = Documents.hashDIDDocument(didDoc);
        LegacyTx.Signed tx = generateDIDCreateTransaction(didType, docHash, didAddr, issuerAddr, issuerSig,
                Config.withDIDConfig(cfg));
        DIDTxResult r = new DIDTxResult();
        r.did = didIdentifier;
        r.document = didDoc;
        r.transaction = tx;
        return r;
    }

    /**
     * Go GenerateIssuerSignature: resolves the configuration (capId auto-generated when empty); with
     * {@code syncEpoch} the epoch is read from the chain.
     */
    @SafeVarargs
    public final Issuer.IssuerSignature generateIssuerSignature(int didType, String didAddr, String issuerAddr,
            Consumer<Config>... options) throws Exception {
        Config cfg = resolve(options);
        if (cfg.syncEpoch) {
            try {
                cfg.epoch = didContract.getCapabilityEpoch(issuerAddr);
            } catch (Exception e) {
                throw new Exception("failed to get capability epoch: " + e.getMessage(), e);
            }
        }
        if (cfg.issuerSigner == null) {
            throw new Exception("issuer signer is required");
        }
        Issuer.IssueDIDPayload p = new Issuer.IssueDIDPayload();
        p.contractAddress = this.baseConfig.didSmcAddr;
        p.issuerAddress = issuerAddr;
        p.didAddress = didAddr;
        p.didType = didType;
        p.epoch = cfg.epoch;
        p.capId = cfg.capId;
        try {
            return Issuer.generateIssueDIDSignature(p, cfg.issuerSigner);
        } catch (Exception e) {
            throw new Exception("failed to create issuer signature: " + e.getMessage(), e);
        }
    }

    public Issuer.IssuerSignature generateIssuerSignature(int didType, String didAddr, String issuerAddr, Config cfg)
            throws Exception {
        return generateIssuerSignature(didType, didAddr, issuerAddr, Config.withDIDConfig(cfg));
    }

    /** Go GenerateDIDCreateTransaction; with {@code syncNonce} the DID's nonce is read from the chain. */
    @SafeVarargs
    public final LegacyTx.Signed generateDIDCreateTransaction(int didType, String docHash, String didAddr,
            String issuerAddr, Issuer.IssuerSignature issuerSig, Consumer<Config>... options) throws Exception {
        Config cfg = resolve(options);
        if (cfg.didSigner == null) {
            throw new Exception("did signer is required");
        }
        if (cfg.syncNonce) {
            cfg.nonce = syncedNonce(didAddr);
        }
        return didContract.createDIDTx(issuerAddr, didType, docHash, cfg.capId, issuerSig, cfg.nonce, cfg.didSigner);
    }

    public LegacyTx.Signed generateDIDCreateTransaction(int didType, String docHash, String didAddr, String issuerAddr,
            Issuer.IssuerSignature issuerSig, Config cfg) throws Exception {
        return generateDIDCreateTransaction(didType, docHash, didAddr, issuerAddr, issuerSig,
                Config.withDIDConfig(cfg));
    }

    @SafeVarargs
    public final LegacyTx.Signed generateSetDocumentHashTransaction(String docHash, String didAddr,
            Issuer.IssuerSignature issuerSig, Consumer<Config>... options) throws Exception {
        Config cfg = resolve(options);
        if (cfg.didSigner == null) {
            throw new Exception("did signer is required");
        }
        if (issuerSig == null) {
            throw new Exception("issuer signature is required");
        }
        if (cfg.syncNonce) {
            cfg.nonce = syncedNonce(didAddr);
        }
        return didContract.setDocumentHashTx(didAddr, docHash, cfg.capId, issuerSig, cfg.nonce, cfg.didSigner);
    }

    public LegacyTx.Signed generateSetDocumentHashTransaction(String docHash, String didAddr,
            Issuer.IssuerSignature issuerSig, Config cfg) throws Exception {
        return generateSetDocumentHashTransaction(docHash, didAddr, issuerSig, Config.withDIDConfig(cfg));
    }

    /** Go GenerateSetDocumentHashByIssuerTransaction: the issuer's nonce is the one synced. */
    @SafeVarargs
    public final LegacyTx.Signed generateSetDocumentHashByIssuerTransaction(String docHash, String didAddr,
            Consumer<Config>... options) throws Exception {
        Config cfg = resolve(options);
        if (cfg.issuerSigner == null) {
            throw new Exception("issuer signer is required");
        }
        if (cfg.syncNonce) {
            cfg.nonce = syncedNonce(cfg.issuerSigner.getAddress());
        }
        return didContract.setDocumentHashByIssuerTx(didAddr, docHash, cfg.nonce, cfg.issuerSigner);
    }

    public LegacyTx.Signed generateSetDocumentHashByIssuerTransaction(String docHash, String didAddr, Config cfg)
            throws Exception {
        return generateSetDocumentHashByIssuerTransaction(docHash, didAddr, Config.withDIDConfig(cfg));
    }

    private long syncedNonce(String address) throws Exception {
        try {
            return didContract.getNonce(address);
        } catch (Exception e) {
            throw new Exception("failed to get nonce: " + e.getMessage(), e);
        }
    }

    @SafeVarargs
    private Config resolve(Consumer<Config>... options) {
        Config cfg = new Config();
        cfg.rpc = baseConfig.rpc;
        cfg.chainId = baseConfig.chainId;
        cfg.didSmcAddr = baseConfig.didSmcAddr;
        cfg.method = baseConfig.method;
        cfg.issuerSigner = baseConfig.issuerSigner;
        cfg.didSigner = baseConfig.didSigner;
        cfg.nonce = baseConfig.nonce;
        cfg.epoch = baseConfig.epoch;
        cfg.capId = baseConfig.capId;
        cfg.syncEpoch = baseConfig.syncEpoch;
        cfg.syncNonce = baseConfig.syncNonce;
        cfg.extraVMs = new ArrayList<>(baseConfig.extraVMs);
        cfg.enableP256VM = baseConfig.enableP256VM;
        cfg.chainClient = baseConfig.chainClient;
        if (options != null) {
            for (Consumer<Config> opt : options) {
                opt.accept(cfg);
            }
        }
        if (cfg.capId == null || cfg.capId.isEmpty()) {
            cfg.capId = Issuer.generateCapID();
        }
        return cfg;
    }
}
