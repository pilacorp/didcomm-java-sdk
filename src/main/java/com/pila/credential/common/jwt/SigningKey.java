package com.pila.credential.common.jwt;

import com.pila.credential.common.crypto.Crypto;
import com.pila.credential.common.verificationmethod.DocumentResolver;
import com.pila.credential.common.verificationmethod.ResolveVmUrl;
import com.pila.credential.common.verificationmethod.VerificationMethodEntry;
import com.pila.credential.common.verificationmethod.VerificationMethodKeyKind;
import com.pila.credential.common.verificationmethod.VerificationMethodMaterial;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;

/**
 * The verification method a JWT is issued under: the {@code kid} and {@code alg} its header carries
 * and the public key a fresh signature must verify against (Go {@code jwt.SigningKey}).
 * {@link #NONE} stands for a parsed token.
 */
public final class SigningKey {
    public static final SigningKey NONE = new SigningKey(null, null, null);

    private final String id;
    private final String alg;
    private final PublicKey publicKey;

    private SigningKey(String id, String alg, PublicKey publicKey) {
        this.id = id;
        this.alg = alg;
        this.publicKey = publicKey;
    }

    public String id() {
        return id;
    }

    public String alg() {
        return alg;
    }

    /**
     * Resolves the pinned VM (or the latest active one for {@code purpose}) and derives the JOSE alg from the
     * key it holds, so a P-256 issuer gets ES256 and a secp256k1 issuer ES256K.
     */
    public static SigningKey resolve(String did, String purpose, String pinnedKey, DocumentResolver resolver)
            throws Exception {
        ResolveVmUrl.SigningVM signing = ResolveVmUrl.resolveSigningVM(did, purpose, pinnedKey, resolver);
        VerificationMethodEntry vm = signing.vm();
        String alg = switch (VerificationMethodKeyKind.fromEntry(vm)) {
            case P256 -> "ES256";
            case SECP256K1 -> "ES256K";
            default -> throw new Exception("verification method " + signing.url()
                    + " has an unrecognized or unsupported key type for JWT signing");
        };
        PublicKey pub = VerificationMethodMaterial.ecPublicKeyFromEntry(vm);
        return new SigningKey(signing.url(), alg, pub);
    }

    /**
     * Checks a raw signature over {@code signingInput} against the key and returns it base64url-encoded.
     * A 65-byte r||s||v signature is trimmed; anything but 64 bytes is a signer returning the wrong format.
     * A {@link #NONE} key skips the key check but not the shape check.
     */
    public String accept(String signingInput, byte[] signature) throws Exception {
        if (signature != null && signature.length == 65) {
            signature = Arrays.copyOf(signature, 64);
        }
        if (signature == null || signature.length != 64) {
            throw new Exception("signature must be 64-byte r||s (65 with a trailing recovery id is trimmed), got "
                    + (signature == null ? 0 : signature.length)
                    + " bytes: the signer returned another format, not a JWS signature");
        }
        if (publicKey != null) {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(signingInput.getBytes(StandardCharsets.UTF_8));
            if (!Crypto.verifyEcdsaRaw(publicKey, digest, signature)) {
                throw new Exception("the signature does not verify against verification method " + id
                        + ": it was made by another key or over data other than the signing input");
            }
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
    }
}
