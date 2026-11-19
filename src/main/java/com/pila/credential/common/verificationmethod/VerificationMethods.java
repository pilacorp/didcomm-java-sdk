package com.pila.credential.common.verificationmethod;

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Verification method / DID document builders (Go static_resolver.go: NewDIDDocument, NewSecp256k1VM, NewRSAVM,
 * NewP256VM, NewP256MultikeyVM).
 */
public final class VerificationMethods {
    private VerificationMethods() {
    }

    /** A document exposing {@code vms}, each listed under both assertionMethod and authentication. */
    public static DIDDocument newDIDDocument(String did, VerificationMethodEntry... vms) {
        List<String> ids = new ArrayList<>();
        for (VerificationMethodEntry vm : vms) {
            ids.add(vm.getId());
        }
        DIDDocument doc = new DIDDocument();
        doc.setId(did);
        doc.setVerificationMethod(new ArrayList<>(List.of(vms)));
        doc.setAssertionMethod(new ArrayList<>(ids));
        doc.setAuthentication(new ArrayList<>(ids));
        return doc;
    }

    private static VerificationMethodEntry base(String did, String fragment, String type) {
        VerificationMethodEntry vm = new VerificationMethodEntry();
        vm.setId(did + "#" + fragment);
        vm.setType(type);
        vm.setController(did);
        return vm;
    }

    /** EcdsaSecp256k1VerificationKey2019 from a public key hex (0x04||X||Y). */
    public static VerificationMethodEntry newSecp256k1VM(String did, String fragment, String pubKeyHex) {
        VerificationMethodEntry vm = base(did, fragment, "EcdsaSecp256k1VerificationKey2019");
        vm.setPublicKeyHex(pubKeyHex);
        return vm;
    }

    /** JsonWebKey2020 from an RSA public key (JsonWebSignature2020). */
    public static VerificationMethodEntry newRSAVM(String did, String fragment, RSAPublicKey pub) {
        VerificationMethodEntry vm = base(did, fragment, "JsonWebKey2020");
        JWK jwk = new JWK();
        jwk.setKty("RSA");
        jwk.setN(b64(unsigned(pub.getModulus())));
        jwk.setE(b64(unsigned(pub.getPublicExponent())));
        vm.setPublicKeyJwk(jwk);
        return vm;
    }

    /** JsonWebKey2020 from a P-256 public key. */
    public static VerificationMethodEntry newP256VM(String did, String fragment, ECPublicKey pub) throws Exception {
        if (pub == null) {
            throw new Exception("NewP256VM requires a non-nil public key");
        }
        requireP256(pub);
        VerificationMethodEntry vm = base(did, fragment, "JsonWebKey2020");
        JWK jwk = new JWK();
        jwk.setKty("EC");
        jwk.setCrv("P-256");
        jwk.setX(b64(fixed(pub.getW().getAffineX(), 32)));
        jwk.setY(b64(fixed(pub.getW().getAffineY(), 32)));
        vm.setPublicKeyJwk(jwk);
        return vm;
    }

    /** Multikey from a P-256 public key (the representation the W3C ecdsa suites specify). */
    public static VerificationMethodEntry newP256MultikeyVM(String did, String fragment, ECPublicKey pub)
            throws Exception {
        if (pub == null) {
            throw new Exception("NewP256MultikeyVM requires a P-256 key");
        }
        requireP256(pub);
        VerificationMethodEntry vm = base(did, fragment, "Multikey");
        vm.setPublicKeyMultibase(Multikey.encodePublicKey(pub));
        return vm;
    }

    private static void requireP256(ECPublicKey pub) throws Exception {
        if (pub.getParams().getOrder().bitLength() != 256
                || !pub.getParams().getOrder().toString(16).startsWith("ffffffff00000000ffffffffffffffff")) {
            throw new Exception("requires a P-256 key");
        }
    }

    private static byte[] unsigned(BigInteger v) {
        byte[] b = v.toByteArray();
        if (b.length > 1 && b[0] == 0) {
            return java.util.Arrays.copyOfRange(b, 1, b.length);
        }
        return b;
    }

    private static byte[] fixed(BigInteger v, int len) {
        byte[] u = unsigned(v);
        if (u.length >= len) {
            return u;
        }
        byte[] out = new byte[len];
        System.arraycopy(u, 0, out, len - u.length, u.length);
        return out;
    }

    private static String b64(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }
}
