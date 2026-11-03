package com.pila.credential.vc;

import com.pila.credential.common.jsonmap.JSONMap;
import com.pila.credential.common.signer.P256SignerProvider;
import com.pila.credential.common.signer.SignerProvider;
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

    public static ECDSASDCredential newCredential(CredentialContents vcc) throws Exception {
        return new ECDSASDCredential(JSONCredential.newJSONCredential(vcc));
    }

    public static ECDSASDCredential parse(byte[] rawJSON) throws Exception {
        return new ECDSASDCredential(JSONCredential.parseJSONCredential(rawJSON));
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
        if (!(signerProvider instanceof P256SignerProvider)) {
            throw new Exception("unsupported key kind for ecdsa-sd-2023 credential");
        }
        JSONMap data = (JSONMap) base.getCredentialData();
        Object issuerObj = data.get("issuer");
        if (!(issuerObj instanceof String issuer) || issuer.isBlank()) {
            throw new Exception("issuer is missing or invalid");
        }
        CredentialResolver resolver = CredentialConfig.getDocumentResolver();
        var signing = ResolveVmUrl.resolveSigningVM(issuer, "assertionMethod", base.getVerificationMethod(), resolver);
        VerificationMethodEntry vm = signing.vm();
        if (VerificationMethodKeyKind.fromEntry(vm) != VerificationMethodKeyKind.P256) {
            throw new Exception("ecdsa-sd-2023 requires a P-256 verification method");
        }
        PublicKey vmPub = resolver.ecPublicKeyFromEntry(vm);
        data.addECDSASDBaseProof(signerProvider, signing.url(), "assertionMethod", dotPathsToPointers(mandatoryPaths),
                vmPub);
    }

    public JSONCredential derive(List<String> selectivePaths) throws Exception {
        JSONMap derived = ((JSONMap) base.getCredentialData()).deriveECDSASD(dotPathsToPointers(selectivePaths));
        return JSONCredential.parseJSONCredential(derived.toJSON());
    }

    @Override
    public void addProof(String privKeyHex) throws Exception {
        addProofByProvider(new P256SignerProvider(privKeyHex), List.of());
    }

    @Override
    public void addProofByProvider(SignerProvider signerProvider) throws Exception {
        addProofByProvider(signerProvider, List.of());
    }

    @Override
    public byte[] getSigningInput() throws Exception {
        return base.getSigningInput();
    }

    @Override
    public byte[] createProofSigning(byte[] docHash, com.pila.credential.common.dto.Proof proof) throws Exception {
        return base.createProofSigning(docHash, proof);
    }

    @Override
    public void addCustomProof(com.pila.credential.common.dto.Proof proof) throws Exception {
        base.addCustomProof(proof);
    }

    @Override
    public void verify() throws Exception {
        base.verify();
    }

    @Override
    public Object serialize() throws Exception {
        return base.serialize();
    }

    @Override
    public byte[] getContents() throws Exception {
        return base.getContents();
    }

    @Override
    public String getType() {
        return base.getType();
    }

    public JSONCredential getBase() {
        return base;
    }
}
