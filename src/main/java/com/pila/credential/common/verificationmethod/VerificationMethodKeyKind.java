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
        }
        if (vm.getPublicKeyHex() != null && !vm.getPublicKeyHex().isEmpty()) {
            return SECP256K1;
        }
        return UNKNOWN;
    }
}
