package com.pila.credential.didv2;

import com.pila.credential.didv2.didcontract.ChainClient;
import com.pila.credential.didv2.didcontract.Contract;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public final class Config {
    public static final String DEFAULT_RPC = "https://rpc-new.pila.vn";
    public static final long DEFAULT_CHAIN_ID = 704L;
    public static final String DEFAULT_DID_SMC_ADDRESS = "0x75e7b09a24bce5a921babe27b62ec7bfe2230d6a";
    public static final String DEFAULT_METHOD = "did:nda";

    public String rpc = DEFAULT_RPC;
    public long chainId = DEFAULT_CHAIN_ID;
    public String didSmcAddr = DEFAULT_DID_SMC_ADDRESS;
    public String method = DEFAULT_METHOD;
    public Signer issuerSigner;
    public Signer didSigner;
    public long nonce;
    public long epoch;
    public String capId = "";
    public boolean syncEpoch;
    public boolean syncNonce;
    public List<Documents.VmSpec> extraVMs = new ArrayList<>();
    public boolean enableP256VM;
    /** Optional node access (default: JSON-RPC over {@link #rpc}); inject a client in tests. */
    public ChainClient chainClient;

    public static Config defaults() {
        return new Config();
    }

    @SafeVarargs
    public static Config apply(Consumer<Config>... options) {
        Config c = defaults();
        for (Consumer<Config> opt : options) {
            opt.accept(c);
        }
        return c;
    }

    public Contract contract() {
        return new Contract(rpc, didSmcAddr, chainId, Contract.DEFAULT_GAS_LIMIT, java.math.BigInteger.ZERO,
                chainClient != null ? chainClient
                        : rpc == null || rpc.isEmpty() ? null : new com.pila.credential.didv2.didcontract.JsonRpcClient(rpc));
    }

    // Named options (Go WithRPC, WithDIDChainID, ...), for Config.apply(...) and the generator's per-call options.

    public static Consumer<Config> withRPC(String rpc) {
        return c -> c.rpc = rpc;
    }

    public static Consumer<Config> withDIDChainID(long chainId) {
        return c -> c.chainId = chainId;
    }

    public static Consumer<Config> withDIDAddressSMC(String addr) {
        return c -> c.didSmcAddr = addr;
    }

    public static Consumer<Config> withMethod(String method) {
        return c -> c.method = method;
    }

    public static Consumer<Config> withEpoch(long epoch) {
        return c -> c.epoch = epoch;
    }

    public static Consumer<Config> withIssuerSignerProvider(Signer p) {
        return c -> c.issuerSigner = p;
    }

    public static Consumer<Config> withDIDSignerProvider(Signer p) {
        return c -> c.didSigner = p;
    }

    public static Consumer<Config> withSyncEpoch(boolean sync) {
        return c -> c.syncEpoch = sync;
    }

    public static Consumer<Config> withSyncNonce(boolean sync) {
        return c -> c.syncNonce = sync;
    }

    public static Consumer<Config> withNonce(long nonce) {
        return c -> c.nonce = nonce;
    }

    public static Consumer<Config> withCapID(String capId) {
        return c -> c.capId = capId;
    }

    public static Consumer<Config> withVerificationMethods(Documents.VmSpec... specs) {
        return c -> c.extraVMs.addAll(List.of(specs));
    }

    public static Consumer<Config> withP256VerificationMethod() {
        return c -> c.enableP256VM = true;
    }

    public static Consumer<Config> withChainClient(ChainClient client) {
        return c -> c.chainClient = client;
    }

    /** Go WithDIDConfig: copies a whole configuration (the registry address is lower-cased). */
    public static Consumer<Config> withDIDConfig(Config config) {
        return c -> {
            c.rpc = config.rpc;
            c.chainId = config.chainId;
            c.didSmcAddr = config.didSmcAddr == null ? null : config.didSmcAddr.toLowerCase(java.util.Locale.ROOT);
            c.method = config.method;
            c.issuerSigner = config.issuerSigner;
            c.didSigner = config.didSigner;
            c.capId = config.capId;
            c.epoch = config.epoch;
            c.nonce = config.nonce;
            c.syncEpoch = config.syncEpoch;
            c.syncNonce = config.syncNonce;
            c.extraVMs = new ArrayList<>(config.extraVMs);
            c.enableP256VM = config.enableP256VM;
            c.chainClient = config.chainClient;
        };
    }
}
