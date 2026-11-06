package com.pila.credential.common.verificationmethod;

/**
 * Key kinds a verification method can hold (go-credential-sdk VMKeyKind / KeyKind).
 * {@code UNKNOWN} is the "not recognized" result of {@code VMKeyKind}.
 */
public enum VerificationMethodKeyKind {
    P256,
    SECP256K1,
    RSA,
    UNKNOWN;

    /** Go KeyKind.String(). */
    public String label() {
        return switch (this) {
            case SECP256K1 -> "secp256k1";
            case RSA -> "RSA";
            case P256 -> "P-256";
            default -> "unknown";
        };
    }

    /** Go VMIsRSA: an RSA JWK. */
    public static boolean vmIsRSA(VerificationMethodEntry vm) {
        return vm != null && vm.getPublicKeyJwk() != null && "RSA".equals(vm.getPublicKeyJwk().getKty());
    }

    /** Go VMIsP256: an EC P-256 JWK or a P-256 Multikey. */
    public static boolean vmIsP256(VerificationMethodEntry vm) {
        if (vm == null) {
            return false;
        }
        JWK jwk = vm.getPublicKeyJwk();
        if (jwk != null) {
            return "EC".equals(jwk.getKty()) && "P-256".equals(jwk.getCrv());
        }
        String mb = vm.getPublicKeyMultibase();
        return mb != null && !mb.isEmpty() && Multikey.isP256PublicMultibase(mb);
    }

    /** Go VMIsSecp256k1: an EC secp256k1 JWK or any publicKeyHex. */
    public static boolean vmIsSecp256k1(VerificationMethodEntry vm) {
        if (vm == null) {
            return false;
        }
        JWK jwk = vm.getPublicKeyJwk();
        if (jwk != null) {
            return "EC".equals(jwk.getKty()) && "secp256k1".equals(jwk.getCrv());
        }
        return vm.getPublicKeyHex() != null && !vm.getPublicKeyHex().isEmpty();
    }

    /** Go VMKeyKind; {@link #UNKNOWN} when the key is not recognized. */
    public static VerificationMethodKeyKind fromEntry(VerificationMethodEntry vm) {
        if (vmIsSecp256k1(vm)) {
            return SECP256K1;
        }
        if (vmIsP256(vm)) {
            return P256;
        }
        if (vmIsRSA(vm)) {
            return RSA;
        }
        return UNKNOWN;
    }

    boolean matches(VerificationMethodEntry vm) {
        return switch (this) {
            case RSA -> vmIsRSA(vm);
            case P256 -> vmIsP256(vm);
            case SECP256K1 -> vmIsSecp256k1(vm);
            default -> false;
        };
    }
}
