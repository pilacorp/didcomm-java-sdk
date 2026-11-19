package com.pila.credential.common.verificationmethod;

import java.util.List;

/**
 * Resolves P-256 {@code did:key} identifiers without HTTP (W3C ecdsa-rdfc-2019 vectors).
 */
public final class DidKeyP256Resolver implements CredentialResolver {

    @Override
    public DIDDocument resolveDocument(String did) throws Exception {
        if (did == null || !did.startsWith("did:key:")) {
            throw new Exception("DidKeyP256Resolver: unsupported DID " + did);
        }
        String multibaseKey = did.substring("did:key:".length());
        Multikey.publicKeyFromMultibase(multibaseKey);
        String vmId = did + "#" + multibaseKey;
        VerificationMethodEntry vm = new VerificationMethodEntry();
        vm.setId(vmId);
        vm.setType("Multikey");
        vm.setController(did);
        vm.setPublicKeyMultibase(multibaseKey);

        DIDDocument doc = new DIDDocument();
        doc.setId(did);
        doc.setVerificationMethod(List.of(vm));
        doc.setAuthentication(List.of(vmId));
        doc.setAssertionMethod(List.of(vmId));
        return doc;
    }
}
