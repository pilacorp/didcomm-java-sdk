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

    /**
     * Go ECPubFromVM: publicKeyHex (read as secp256k1, whatever the VM type), then publicKeyJwk (secp256k1, P-256
     * or P-384), then publicKeyMultibase (P-256 or P-384, curve from the multicodec prefix).
     */
    public static PublicKey ecPublicKeyFromEntry(VerificationMethodEntry vm) throws Exception {
        if (vm == null) {
            throw new Exception("verification method is nil");
        }
        if (vm.getPublicKeyHex() != null && !vm.getPublicKeyHex().isEmpty()) {
            return secp256k1PubFromHex(vm.getPublicKeyHex());
        }
        if (vm.getPublicKeyJwk() != null) {
            return ecPubFromJwk(vm.getPublicKeyJwk());
        }
        if (vm.getPublicKeyMultibase() != null && !vm.getPublicKeyMultibase().isEmpty()) {
            return Multikey.decodeEc(vm.getPublicKeyMultibase()).toPublicKey();
        }
        throw new Exception("verification method '" + vm.getId() + "' has no public key material");
    }

    /** Go stripHexPrefix: a leading "0x" or "0X"; the rest must be ASCII hex. */
    static byte[] strictHex(String s, String what) throws Exception {
        String h = s.length() >= 2 && s.charAt(0) == '0' && (s.charAt(1) == 'x' || s.charAt(1) == 'X')
                ? s.substring(2)
                : s;
        if (h.length() % 2 != 0) {
            throw new Exception(what + ": odd length hex string");
        }
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = asciiHexDigit(h.charAt(i * 2));
            int lo = asciiHexDigit(h.charAt(i * 2 + 1));
            if (hi < 0 || lo < 0) {
                throw new Exception(what + ": invalid byte in hex string");
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    private static int asciiHexDigit(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    /** Go Secp256k1PubFromHex: 33-byte compressed (02/03) or 65-byte uncompressed (04), on the curve. */
    public static PublicKey secp256k1PubFromHex(String h) throws Exception {
        byte[] b = strictHex(h, "decode secp256k1 public key hex");
        if (!((b.length == 33 && (b[0] == 0x02 || b[0] == 0x03)) || (b.length == 65 && b[0] == 0x04))) {
            throw new Exception("secp256k1 public key: want 33 compressed or 65 uncompressed bytes, got " + b.length);
        }
        X9ECParameters ecParams = CustomNamedCurves.getByName("secp256k1");
        ECPoint point;
        try {
            point = ecParams.getCurve().decodePoint(b);
        } catch (Exception e) {
            throw new Exception("invalid secp256k1 public key: " + e.getMessage(), e);
        }
        if (point.isInfinity() || !point.isValid()) {
            throw new Exception("invalid secp256k1 public key");
        }
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        return kf.generatePublic(new org.bouncycastle.jce.spec.ECPublicKeySpec(point,
                ECNamedCurveTable.getParameterSpec("secp256k1")));
    }

    private static byte[] rawUrlDecode(String s, String what) throws Exception {
        if (s == null || s.indexOf('=') >= 0) {
            throw new Exception("failed to decode " + what + ": illegal base64url data");
        }
        try {
            return Base64.getUrlDecoder().decode(s.replace("\r", "").replace("\n", ""));
        } catch (IllegalArgumentException e) {
            throw new Exception("failed to decode " + what + ": " + e.getMessage(), e);
        }
    }

    /**
     * Go ECPubFromJWK: an EC JWK on secp256k1, P-256 or P-384, RawURL coordinates (a short one is left-padded, a
     * longer one refused), off-curve points rejected.
     */
    public static PublicKey ecPubFromJwk(JWK jwk) throws Exception {
        if (jwk == null) {
            throw new Exception("jwk is nil");
        }
        if (!"EC".equals(jwk.getKty())) {
            throw new Exception("unsupported key type: " + jwk.getKty());
        }
        String crv = jwk.getCrv();
        String custom;
        String named;
        int size;
        if ("secp256k1".equals(crv)) {
            custom = "secp256k1";
            named = "secp256k1";
            size = 32;
        } else if ("P-256".equals(crv)) {
            custom = "P-256";
            named = "prime256v1";
            size = 32;
        } else if ("P-384".equals(crv)) {
            custom = "P-384";
            named = "secp384r1";
            size = 48;
        } else {
            throw new Exception("unsupported curve: " + crv + " (want secp256k1, P-256 or P-384)");
        }
        byte[] xBytes = rawUrlDecode(jwk.getX(), "X coordinate");
        byte[] yBytes = rawUrlDecode(jwk.getY(), "Y coordinate");
        if (xBytes.length > size || yBytes.length > size) {
            throw new Exception("jwk " + crv + ": coordinates must be at most " + size + " bytes, got x="
                    + xBytes.length + " y=" + yBytes.length);
        }
        X9ECParameters ecParams = CustomNamedCurves.getByName(custom);
        ECPoint point;
        try {
            point = ecParams.getCurve().validatePoint(new BigInteger(1, xBytes), new BigInteger(1, yBytes));
        } catch (Exception e) {
            throw new Exception("jwk " + crv + ": invalid public key point: " + e.getMessage(), e);
        }
        if (point.isInfinity()) {
            throw new Exception("jwk " + crv + ": invalid public key point");
        }
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        return kf.generatePublic(new org.bouncycastle.jce.spec.ECPublicKeySpec(point,
                ECNamedCurveTable.getParameterSpec(named)));
    }

    /** Go P256PubKeyFromJWK: crv=P-256 only. */
    public static PublicKey p256PubKeyFromJwk(JWK jwk) throws Exception {
        if (jwk == null) {
            throw new Exception("jwk is nil");
        }
        if (!"P-256".equals(jwk.getCrv())) {
            throw new Exception("unsupported curve: " + jwk.getCrv() + " (want P-256)");
        }
        return ecPubFromJwk(jwk);
    }

    /** Go RSAPubKeyFromJWK. */
    public static java.security.interfaces.RSAPublicKey rsaPubKeyFromJwk(JWK jwk) throws Exception {
        if (jwk == null) {
            throw new Exception("jwk is nil");
        }
        if (!"RSA".equals(jwk.getKty())) {
            throw new Exception("unsupported key type: " + jwk.getKty());
        }
        if (jwk.getN() == null || jwk.getN().isEmpty() || jwk.getE() == null || jwk.getE().isEmpty()) {
            throw new Exception("RSA jwk missing n or e");
        }
        BigInteger n = new BigInteger(1, rawUrlDecode(jwk.getN(), "n"));
        BigInteger e = new BigInteger(1, rawUrlDecode(jwk.getE(), "e"));
        return (java.security.interfaces.RSAPublicKey) java.security.KeyFactory.getInstance("RSA")
                .generatePublic(new java.security.spec.RSAPublicKeySpec(n, e));
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

    /**
     * Go DIDFromVerificationMethodURL: the DID before the first '#'; the URL must carry a '#' and start with
     * "did:".
     */
    public static String didFromVerificationMethodURL(String verificationMethodURL) throws Exception {
        if (verificationMethodURL == null || verificationMethodURL.isEmpty()) {
            throw new Exception("verification method is empty");
        }
        int hashIndex = verificationMethodURL.indexOf('#');
        if (hashIndex <= 0) {
            throw new Exception("invalid verification method URL, could not extract DID: " + verificationMethodURL);
        }
        String didPart = verificationMethodURL.substring(0, hashIndex);
        if (!didPart.startsWith("did:")) {
            throw new Exception("extracted DID '" + didPart + "' is invalid, must start with 'did:'");
        }
        return didPart;
    }

    private static PublicKey jwkToPublicKey(JWK jwk) throws Exception {
        return ecPubFromJwk(jwk);
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
}
