package com.pila.credential.common.verificationmethod;

/**
 * Key kinds supported for JSON-LD signing (matches go-credential-sdk VMKeyKind).
 */
public enum VerificationMethodKeyKind {
    P256,
    SECP256K1,
    UNKNOWN;

    public static VerificationMethodKeyKind fromEntry(VerificationMethodEntry vm) {
        if (vm == null) {
            return UNKNOWN;
        }
        if (vm.getPublicKeyJwk() != null) {
            String crv = vm.getPublicKeyJwk().getCrv();
            if ("P-256".equals(crv)) {
                return P256;
            }
            if ("secp256k1".equals(crv)) {
                return SECP256K1;
            }
            return UNKNOWN;
        }
        if (vm.getPublicKeyMultibase() != null && !vm.getPublicKeyMultibase().isEmpty()) {
            try {
                return Multikey.kindFromMultibase(vm.getPublicKeyMultibase());
            } catch (Exception e) {
                return UNKNOWN;
            }
        }
        if (vm.getPublicKeyHex() != null && !vm.getPublicKeyHex().isEmpty()) {
            String type = vm.getType();
            if (type != null && !type.isEmpty()
                    && !"EcdsaSecp256k1VerificationKey2019".equals(type)
                    && !"EcdsaSecp256k1Signature2019".equals(type)) {
                return UNKNOWN;
            }
            return SECP256K1;
        }
        return UNKNOWN;
    }
}
