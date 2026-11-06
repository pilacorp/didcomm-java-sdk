package com.pila.credential.vc;

import com.pila.credential.common.jsonmap.JSONMap;
import com.pila.credential.common.signer.SignerProvider;
import com.pila.credential.common.util.Vcdm;
import com.pila.credential.common.verificationmethod.CredentialResolver;
import com.pila.credential.common.verificationmethod.ResolveVmUrl;
import com.pila.credential.common.verificationmethod.VerificationMethodEntry;
import com.pila.credential.common.verificationmethod.VerificationMethodKeyKind;

import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public final class ECDSASDCredential implements Credential {

    private final JSONCredential base;

    private ECDSASDCredential(JSONCredential base) {
        this.base = base;
    }

    public static ECDSASDCredential newECDSASDCredential(CredentialContents vcc, CredentialOptions opts)
            throws Exception {
        return newCredential(vcc, opts);
    }

    public static ECDSASDCredential parseECDSASDCredential(byte[] rawJSON, CredentialOptions opts) throws Exception {
        return parse(rawJSON, opts);
    }

    public static ECDSASDCredential newCredential(CredentialContents vcc) throws Exception {
        return newCredential(vcc, null);
    }

    public static ECDSASDCredential newCredential(CredentialContents vcc, CredentialOptions opts) throws Exception {
        return new ECDSASDCredential(JSONCredential.newJSONCredential(vcc, opts));
    }

    public static ECDSASDCredential parse(byte[] rawJSON) throws Exception {
        return parse(rawJSON, null);
    }

    public static ECDSASDCredential parse(byte[] rawJSON, CredentialOptions opts) throws Exception {
        return new ECDSASDCredential(JSONCredential.parseJSONCredential(rawJSON, opts));
    }

    public static List<String> dotPathsToPointers(List<String> paths) {
        return paths.stream()
                .filter(p -> p != null && !p.isBlank())
                .map(p -> {
                    if (p.startsWith("/")) {
                        return p;
                    }
                    return "/" + Arrays.stream(p.split("\\."))
                            .map(seg -> seg.replace("~", "~0").replace("/", "~1"))
                            .collect(Collectors.joining("/"));
                })
                .collect(Collectors.toList());
    }

    public void addProofByProvider(SignerProvider signerProvider, List<String> mandatoryPaths) throws Exception {
        addProofByProvider(signerProvider, mandatoryPaths, null);
    }

    /**
     * Signs the credential into an ecdsa-sd-2023 base proof; mandatoryPaths are always disclosed. The proof is
     * bound to the VM {@code withVerificationMethodKey} pins (default: latest active assertionMethod VM), which
     * must hold a P-256 key; any P-256 provider works.
     */
    public void addProofByProvider(SignerProvider signerProvider, List<String> mandatoryPaths,
            CredentialOptions opts) throws Exception {
        if (signerProvider == null) {
            throw new IllegalArgumentException("signer provider cannot be null");
        }
        CredentialOptions o = CredentialOptions.orEmpty(opts);
        CredentialSupport.refuseReplaceOnJSONLD(o);
        JSONMap data = base.getCredentialData();
        base.executeOptionsForSigning(o);
        String issuer = Vcdm.didFromField(data.get("issuer"));
        if (issuer == null) {
            throw new Exception("issuer is missing or invalid");
        }
        CredentialResolver resolver = o.effectiveResolver();
        var signing = ResolveVmUrl.resolveSigningVM(issuer, "assertionMethod", o.getVerificationMethodKey(), resolver);
        VerificationMethodEntry vm = signing.vm();
        VerificationMethodKeyKind kind = VerificationMethodKeyKind.fromEntry(vm);
        if (kind != VerificationMethodKeyKind.P256) {
            throw new Exception("unsupported key kind " + kind + " for ecdsa-sd-2023 credential");
        }
        PublicKey vmPub = resolver.ecPublicKeyFromEntry(vm);
        data.addECDSASDBaseProof(signerProvider, signing.url(), "assertionMethod",
                dotPathsToPointers(mandatoryPaths == null ? List.of() : mandatoryPaths), vmPub);
    }

    public JSONCredential derive(List<String> selectivePaths) throws Exception {
        JSONMap derived = ((JSONMap) base.getCredentialData()).deriveECDSASD(dotPathsToPointers(selectivePaths));
        return JSONCredential.parseJSONCredential(derived.toJSON());
    }

    @Override
    public void verify(CredentialOptions opts) throws Exception {
        base.verify(opts);
    }

    @Override
    public Object serialize() throws Exception {
        return base.serialize();
    }

    @Override
    public String hash() throws Exception {
        return base.hash();
    }

    @Override
    public byte[] getContents() throws Exception {
        return base.getContents();
    }

    @Override
    public String getType() {
        return base.getType();
    }

    @Override
    public Object extractField(String path) {
        return base.extractField(path);
    }

    public JSONCredential getBase() {
        return base;
    }
}
