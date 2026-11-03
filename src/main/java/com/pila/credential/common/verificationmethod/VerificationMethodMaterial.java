package com.pila.credential.common.verificationmethod;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;

/**
 * Shared verification-method key material decoding (Go parity with key_material.go).
 */
public final class VerificationMethodMaterial {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private VerificationMethodMaterial() {
    }

    public static VerificationMethodEntry findVerificationMethod(CredentialResolver resolver,
            String verificationMethodURL) throws Exception {
        String didPart = didFromVerificationMethodURL(verificationMethodURL);
        DIDDocument doc = resolver.resolveDocument(didPart);
        if (doc.getVerificationMethod() != null) {
            for (VerificationMethodEntry vm : doc.getVerificationMethod()) {
                if (verificationMethodURL.equals(vm.getId())) {
                    return vm;
                }
            }
        }
        throw new Exception("verification method '" + verificationMethodURL + "' not found in DID document");
    }

    public static PublicKey ecPublicKeyFromEntry(VerificationMethodEntry vm) throws Exception {
        if (vm.getPublicKeyJwk() != null) {
            return jwkToPublicKey(vm.getPublicKeyJwk());
        }
        if (vm.getPublicKeyMultibase() != null && !vm.getPublicKeyMultibase().isEmpty()) {
            return Multikey.publicKeyFromMultibase(vm.getPublicKeyMultibase());
        }
        if (vm.getPublicKeyHex() != null && !vm.getPublicKeyHex().isEmpty()) {
            if (VerificationMethodKeyKind.fromEntry(vm) != VerificationMethodKeyKind.SECP256K1) {
                throw new Exception("publicKeyHex is only valid for secp256k1 verification methods, got type "
                        + vm.getType());
            }
            String hex = vm.getPublicKeyHex().startsWith("0x") ? vm.getPublicKeyHex().substring(2)
                    : vm.getPublicKeyHex();
            byte[] pubBytes = hexStringToBytes(hex);
            X9ECParameters ecParams = CustomNamedCurves.getByName("secp256k1");
            ECPoint point = ecParams.getCurve().decodePoint(pubBytes);
            KeyFactory kf = KeyFactory.getInstance("EC", "BC");
            return kf.generatePublic(new org.bouncycastle.jce.spec.ECPublicKeySpec(point,
                    ECNamedCurveTable.getParameterSpec("secp256k1")));
        }
        throw new Exception("no public key in verification method " + vm.getId());
    }

    public static String getDefaultPublicKeyHex(CredentialResolver resolver, String issuer) throws Exception {
        if (issuer == null || issuer.isEmpty()) {
            throw new Exception("issuer is required");
        }
        if (issuer.indexOf('#') > 0) {
            return publicKeyHexFromEntry(findVerificationMethod(resolver, issuer));
        }
        DIDDocument doc = resolver.resolveDocument(issuer);
        if (doc.getAuthentication() != null) {
            for (String vmId : doc.getAuthentication()) {
                if (vmId != null && !vmId.isEmpty()) {
                    return publicKeyHexFromEntry(findVerificationMethod(resolver, vmId));
                }
            }
        }
        if (doc.getVerificationMethod() != null && !doc.getVerificationMethod().isEmpty()) {
            return publicKeyHexFromEntry(doc.getVerificationMethod().get(0));
        }
        throw new Exception("no public key found for DID '" + issuer + "'");
    }

    public static String getPublicKeyHex(CredentialResolver resolver, String verificationMethodURL) throws Exception {
        return publicKeyHexFromEntry(findVerificationMethod(resolver, verificationMethodURL));
    }

    private static String publicKeyHexFromEntry(VerificationMethodEntry vm) throws Exception {
        if (vm.getPublicKeyHex() != null && !vm.getPublicKeyHex().isEmpty()) {
            String publicKey = vm.getPublicKeyHex();
            return publicKey.startsWith("0x") ? publicKey.substring(2) : publicKey;
        }
        if (vm.getPublicKeyMultibase() != null && !vm.getPublicKeyMultibase().isEmpty()) {
            PublicKey pub = Multikey.publicKeyFromMultibase(vm.getPublicKeyMultibase());
            if (!(pub instanceof org.bouncycastle.jce.interfaces.ECPublicKey ec)) {
                throw new Exception("expected EC public key");
            }
            byte[] encoded = ec.getQ().getEncoded(false);
            StringBuilder hex = new StringBuilder(encoded.length * 2);
            for (byte b : encoded) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        }
        if (vm.getPublicKeyJwk() != null) {
            return jwkSecp256k1ToHex(vm.getPublicKeyJwk());
        }
        throw new Exception("no public key in verification method '" + vm.getId() + "'");
    }

    static String didFromVerificationMethodURL(String verificationMethodURL) throws Exception {
        int hashIndex = verificationMethodURL.indexOf('#');
        if (hashIndex <= 0) {
            throw new Exception("invalid verification method URL: " + verificationMethodURL);
        }
        return verificationMethodURL.substring(0, hashIndex);
    }

    private static PublicKey jwkToPublicKey(JWK jwk) throws Exception {
        if (!"EC".equals(jwk.getKty())) {
            throw new Exception("unsupported key type: " + jwk.getKty());
        }
        byte[] xBytes = Base64.getUrlDecoder().decode(jwk.getX());
        byte[] yBytes = Base64.getUrlDecoder().decode(jwk.getY());
        BigInteger x = new BigInteger(1, xBytes);
        BigInteger y = new BigInteger(1, yBytes);

        String curveName;
        if ("secp256k1".equals(jwk.getCrv())) {
            curveName = "secp256k1";
        } else if ("P-256".equals(jwk.getCrv())) {
            curveName = "prime256v1";
        } else {
            throw new Exception("unsupported curve: " + jwk.getCrv());
        }

        X9ECParameters ecParams = CustomNamedCurves.getByName(curveName);
        if (ecParams == null && "P-256".equals(jwk.getCrv())) {
            ecParams = CustomNamedCurves.getByName("P-256");
        }
        if (ecParams == null) {
            throw new Exception("curve not found: " + jwk.getCrv());
        }
        ECPoint point = ecParams.getCurve().createPoint(x, y);
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        return kf.generatePublic(new org.bouncycastle.jce.spec.ECPublicKeySpec(point,
                ECNamedCurveTable.getParameterSpec(curveName)));
    }

    private static String jwkSecp256k1ToHex(JWK jwk) throws Exception {
        if (!"EC".equals(jwk.getKty()) || !"secp256k1".equals(jwk.getCrv())) {
            throw new Exception("unsupported JWK for hex export");
        }
        PublicKey pub = jwkToPublicKey(jwk);
        byte[] uncompressed = ((org.bouncycastle.jce.interfaces.ECPublicKey) pub).getQ().getEncoded(false);
        StringBuilder hex = new StringBuilder(uncompressed.length * 2);
        for (byte b : uncompressed) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    private static byte[] hexStringToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
