package com.pila.credential.didv2;

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
        return new Contract(rpc, didSmcAddr, chainId);
    }
}
