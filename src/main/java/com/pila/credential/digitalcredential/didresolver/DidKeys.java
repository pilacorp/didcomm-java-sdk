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
            if (jwk == null && mb.isEmpty() && !hx.isEmpty()
                    && "EcdsaSecp256k1VerificationKey2019".equals(vm.get("type"))) {
                return VerificationMethodMaterial.secp256k1PubFromHex(hx);
            }
        } catch (Exception e) {
            return null;
        }
        return null;
    }

    /** P-256 or secp256k1 public JWK (the curves Go's jwk.ToPublicKey reads here). */
    private static PublicKey jwk(Object v) throws Exception {
        if (!(v instanceof Map<?, ?>)) {
            return null;
        }
        JWK j = MAPPER.convertValue(v, JWK.class);
        if (!"P-256".equals(j.getCrv()) && !"secp256k1".equals(j.getCrv())) {
            return null;
        }
        return VerificationMethodMaterial.ecPubFromJwk(j);
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
