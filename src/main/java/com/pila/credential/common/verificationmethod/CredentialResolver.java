package com.pila.credential.common.verificationmethod;

import java.security.PublicKey;

/**
 * DID document resolution plus verification-method lookup (offline or HTTP).
 */
public interface CredentialResolver extends DocumentResolver {

    default VerificationMethodEntry findVerificationMethod(String verificationMethodURL) throws Exception {
        return VerificationMethodMaterial.findVerificationMethod(this, verificationMethodURL);
    }

    default PublicKey ecPublicKeyFromEntry(VerificationMethodEntry vm) throws Exception {
        return VerificationMethodMaterial.ecPublicKeyFromEntry(vm);
    }

    default String getDefaultPublicKeyHex(String issuer) throws Exception {
        return VerificationMethodMaterial.getDefaultPublicKeyHex(this, issuer);
    }
}
