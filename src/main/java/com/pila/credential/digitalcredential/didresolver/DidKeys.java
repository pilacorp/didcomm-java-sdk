package com.pila.credential.digitalcredential.didresolver;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.verificationmethod.JWK;
import com.pila.credential.common.verificationmethod.Multikey;
import com.pila.credential.common.verificationmethod.VerificationMethodMaterial;

import java.security.PublicKey;
import java.util.Map;

/**
 * Key material of a verification method (CID §2.2.1 to §2.2.3, and publicKeyHex of the older
 * EcdsaSecp256k1VerificationKey2019 type). The key is read from its material, which names its curve; the
 * type is read only for publicKeyHex, which does not.
 */
final class DidKeys {
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    private static final int MULTIKEY_MAX_TEXT = 48;

    private DidKeys() {
    }

    /** The one key vm holds, or null. CID §2.2.1 forbids two material properties for one key; "" is absent. */
    static PublicKey publicKey(Map<String, Object> vm) {
        Object jwk = vm.get("publicKeyJwk");
        String mb = vm.get("publicKeyMultibase") instanceof String s ? s : "";
        String hx = vm.get("publicKeyHex") instanceof String s ? s : "";
        try {
            if (jwk != null && mb.isEmpty() && hx.isEmpty()) {
                return jwk(jwk);
            }
            if (jwk == null && !mb.isEmpty() && hx.isEmpty()) {
                return multikey(mb);
            }
            if (jwk == null && mb.isEmpty() && !hx.isEmpty() && !hx.startsWith("0X") // Go strips only "0x"
                    && "EcdsaSecp256k1VerificationKey2019".equals(vm.get("type"))) {
                return VerificationMethodMaterial.secp256k1PubFromHex(hx);
            }
        } catch (Exception e) {
            return null;
        }
        return null;
    }

    /**
     * P-256 or secp256k1 public JWK, as strict as Go's {@code jwk.ToPublicKey}: no private {@code d}, a
     * secp256k1 key's alg/use/key_ops must allow verifying, coordinates exactly 32 bytes of strict base64url.
     */
    private static PublicKey jwk(Object v) throws Exception {
        if (!(v instanceof Map<?, ?> m) || m.containsKey("d") || !"EC".equals(m.get("kty"))) {
            return null;
        }
        Object crv = m.get("crv");
        if (!"P-256".equals(crv) && !"secp256k1".equals(crv)) {
            return null;
        }
        if ("secp256k1".equals(crv)) {
            if (m.containsKey("alg") && !"ES256K".equals(m.get("alg"))) return null;
            if (m.containsKey("use") && !"sig".equals(m.get("use"))) return null;
            if (m.containsKey("key_ops") && !(m.get("key_ops") instanceof java.util.List<?> ops && ops.contains("verify"))) {
                return null;
            }
        }
        if (!(m.get("x") instanceof String x) || !(m.get("y") instanceof String y)
                || !strictCoordinate(x) || !strictCoordinate(y)) {
            return null;
        }
        JWK j = MAPPER.convertValue(v, JWK.class);
        return VerificationMethodMaterial.ecPubFromJwk(j);
    }

    /** RFC 7515 §2 base64url: no padding, line breaks or stray bits, and exactly 32 bytes (Go jose.DecodeSegment). */
    private static boolean strictCoordinate(String s) {
        try {
            byte[] raw = java.util.Base64.getUrlDecoder().decode(s);
            return raw.length == 32 && java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(raw).equals(s);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /** base58-btc Multikey of a P-256 public key; any other header, a secret key's included, skips the method. */
    private static PublicKey multikey(String s) throws Exception {
        if (!s.startsWith("z") || s.length() - 1 > MULTIKEY_MAX_TEXT) {
            return null;
        }
        Multikey.EcKey k = Multikey.decodeEc(s);
        return k.curve() == Multikey.Curve.P256 ? k.toPublicKey() : null;
    }
}
