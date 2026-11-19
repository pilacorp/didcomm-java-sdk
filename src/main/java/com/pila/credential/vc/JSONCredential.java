package com.pila.credential.vc;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.dto.Proof;
import com.pila.credential.common.jsonmap.JSONMap;
import com.pila.credential.common.signer.DefaultSignerProvider;
import com.pila.credential.common.signer.P256SignerProvider;
import com.pila.credential.common.signer.SignerProvider;
import com.pila.credential.common.util.Vcdm;
import com.pila.credential.common.verificationmethod.CredentialResolver;
import com.pila.credential.common.verificationmethod.ResolveVmUrl;
import com.pila.credential.common.verificationmethod.VerificationMethodEntry;
import com.pila.credential.common.verificationmethod.VerificationMethodKeyKind;

import java.security.PublicKey;
import java.util.HexFormat;
import java.util.Map;

/**
 * JSONCredential represents a verifiable credential in JSON format with embedded proof (Data Integrity or
 * EcdsaSecp256k1Signature2019). Proofs are appended to the proof set, never replaced.
 */
public class JSONCredential implements SignableCredential {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private CredentialData credentialData;

    private JSONCredential() {
    }

    public static JSONCredential newJSONCredential(CredentialContents vcc) throws Exception {
        return newJSONCredential(vcc, null);
    }

    /** Creates a JSONCredential from CredentialContents and runs the content options (schema, revocation, ...). */
    public static JSONCredential newJSONCredential(CredentialContents vcc, CredentialOptions opts) throws Exception {
        JSONCredential e = new JSONCredential();
        e.credentialData = CredentialHelper.serializeCredentialContents(vcc);
        e.executeOptions(CredentialOptions.orEmpty(opts));
        return e;
    }

    public static JSONCredential parseJSONCredential(byte[] rawJSON) throws Exception {
        return parseJSONCredential(rawJSON, null);
    }

    /** Parses a JSON-LD credential; with {@code withVerifyProof} the proofs are verified. */
    public static JSONCredential parseJSONCredential(byte[] rawJSON, CredentialOptions opts) throws Exception {
        if (rawJSON == null || rawJSON.length == 0) {
            throw new Exception("JSON string is empty");
        }
        if (!CredentialParser.isJSONCredential(rawJSON)) {
            throw new Exception("invalid JSON format");
        }
        CredentialData m = new CredentialData(MAPPER.readValue(rawJSON, new TypeReference<Map<String, Object>>() {
        }));
        CredentialSupport.requireCredentialProperties(m);

        JSONCredential e = new JSONCredential();
        e.credentialData = m;
        e.executeOptions(CredentialOptions.orEmpty(opts));
        return e;
    }

    /** Signs with a raw P-256 private key (hex scalar), like Go {@code AddProof}. Prefer a provider. */
    @Override
    public void addProof(String privKeyHex, CredentialOptions opts) throws Exception {
        addProofByProvider(new P256SignerProvider(privKeyHex), opts);
    }

    /** Signs with a raw secp256k1 private key (hex); the VM must hold a secp256k1 key. */
    public void addProofSecp256k1(String privKeyHex, CredentialOptions opts) throws Exception {
        addProofByProvider(new DefaultSignerProvider(privKeyHex), opts);
    }

    /**
     * Signs with a provider bound to the VM {@code withVerificationMethodKey} pins, or by default the issuer's only
     * VM / latest active assertionMethod VM. The suite follows the VM key: P-256 gives ecdsa-rdfc-2019, secp256k1
     * gives EcdsaSecp256k1Signature2019. Proofs are appended; {@code withReplaceProof} is refused.
     */
    @Override
    public void addProofByProvider(SignerProvider signerProvider, CredentialOptions opts) throws Exception {
        if (signerProvider == null) {
            throw new IllegalArgumentException("signer provider cannot be null");
        }
        CredentialOptions o = CredentialOptions.orEmpty(opts);
        CredentialSupport.refuseReplaceOnJSONLD(o);
        executeOptions(o.forSigning());

        String issuer = Vcdm.didFromField(credentialData.get("issuer"));
        if (issuer == null) {
            throw new Exception("issuer is missing or invalid");
        }
        CredentialResolver resolver = o.effectiveResolver();
        ResolveVmUrl.SigningVM signing = ResolveVmUrl.resolveSigningVM(
                issuer, "assertionMethod", o.getVerificationMethodKey(), resolver);
        VerificationMethodEntry vm = signing.vm();
        String vmURL = signing.url();
        VerificationMethodKeyKind kind = VerificationMethodKeyKind.fromEntry(vm);
        PublicKey vmPub = switch (kind) {
            case SECP256K1, P256 -> resolver.ecPublicKeyFromEntry(vm);
            default -> throw new Exception("verification method " + vmURL + " has an unrecognized key type");
        };

        JSONMap map = credentialData;
        if (kind == VerificationMethodKeyKind.SECP256K1) {
            map.addEcdsaSecp256k1ProofByProvider(signerProvider, vmURL, "assertionMethod", null, vmPub);
        } else {
            map.addECDSAProofByProvider(signerProvider, vmURL, "assertionMethod", null, vmPub);
        }
    }

    /** SHA-256 of the canonicalized document body; feed it to {@link #createProofSigning}. */
    @Override
    public byte[] getSigningInput() throws Exception {
        return credentialData.getDocumentDigest();
    }

    /** The 32-byte digest an external signer signs: SHA-256 of the hashData built from docHash and the proof options. */
    public byte[] createProofSigning(byte[] docHash, Proof proof) throws Exception {
        return credentialData.createProofSigning(docHash, proof);
    }

    /**
     * Attaches a proof signed outside the SDK. base58btc ("z") proofValue only. With {@code withVerifyProof} the
     * incoming proof alone is checked first (ecdsa-rdfc-2019 only); a failed check leaves the credential untouched.
     */
    @Override
    public void addCustomProof(Proof proof, CredentialOptions opts) throws Exception {
        if (proof == null) {
            throw new IllegalArgumentException("proof cannot be null");
        }
        CredentialOptions o = CredentialOptions.orEmpty(opts);
        CredentialSupport.refuseReplaceOnJSONLD(o);
        if (o.getVerificationMethodKey() != null && !o.getVerificationMethodKey().isEmpty()) {
            throw new Exception("withVerificationMethodKey cannot be applied by addCustomProof: set "
                    + "proof.verificationMethod on the proof you sign");
        }
        if (o.isVerifyProof()) {
            credentialData.verifyDetachedProof(o.effectiveResolver(), proof);
        }
        executeOptions(o.forSigning());
        credentialData.addCustomProof(proof);
    }

    @Override
    public void verify(CredentialOptions opts) throws Exception {
        CredentialOptions o = CredentialOptions.orEmpty(opts).copy();
        o.setVerifyProof(true);
        executeOptions(o);
    }

    @Override
    public Object serialize() throws Exception {
        if (credentialData.get("proof") == null) {
            throw new Exception("credential must have proof before serialization");
        }
        return credentialData.toMap();
    }

    /**
     * SHA-256 (hex) of the JSON-LD canonicalized full credential including proof. A multibase proof is hashed with
     * the library canonicalizer; a legacy hex proof keeps the legacy canonicalizer so anchored digests do not change.
     */
    @Override
    public String hash() throws Exception {
        if (credentialData.get("proof") == null) {
            throw new Exception("credential must have proof before hashing");
        }
        byte[] digest = credentialData.hasMultibaseProof()
                ? credentialData.canonicalizeFullNativeTypes()
                : credentialData.canonicalizeFull();
        return HexFormat.of().formatHex(digest);
    }

    @Override
    public byte[] getContents() throws Exception {
        return credentialData.toJSON();
    }

    @Override
    public String getType() {
        return "JSON";
    }

    @Override
    public Object extractField(String path) {
        return Vcdm.extractField(credentialData, path);
    }

    public CredentialData getCredentialData() {
        return credentialData;
    }

    void executeOptionsForSigning(CredentialOptions o) throws Exception {
        executeOptions(o.forSigning());
    }

    private void executeOptions(CredentialOptions o) throws Exception {
        CredentialSupport.runContentChecks(credentialData, o);
        if (o.isVerifyProof()) {
            boolean ok;
            try {
                ok = credentialData.verifyProof(o.effectiveResolver(), o.getProofVerificationMethod());
            } catch (Exception e) {
                throw new Exception("credential verification failed: verify proof: " + e.getMessage(), e);
            }
            if (!ok) {
                throw new com.pila.credential.common.error.CredentialException(
                        com.pila.credential.common.error.CredentialException.Code.INVALID_PROOF, "invalid proof");
            }
        }
        if (o.isCheckExpiration()) {
            try {
                CredentialSupport.checkExpiration(credentialData, o.getClockSkewLeewayMs());
            } catch (com.pila.credential.common.error.CredentialException e) {
                throw e;
            } catch (Exception e) {
                throw new Exception("failed to check expiration: " + e.getMessage(), e);
            }
        }
    }
}
