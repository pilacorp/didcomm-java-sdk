package com.pila.credential.vp;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.dto.Proof;
import com.pila.credential.common.error.AudienceUnboundException;
import com.pila.credential.common.error.CredentialException;
import com.pila.credential.common.signer.DefaultSignerProvider;
import com.pila.credential.common.signer.P256SignerProvider;
import com.pila.credential.common.signer.SignerProvider;
import com.pila.credential.common.util.Vcdm;
import com.pila.credential.common.verificationmethod.CredentialResolver;
import com.pila.credential.common.verificationmethod.ResolveVmUrl;
import com.pila.credential.common.verificationmethod.VerificationMethodEntry;
import com.pila.credential.common.verificationmethod.VerificationMethodKeyKind;

import java.security.PublicKey;
import java.util.Map;

/**
 * JSON-LD verifiable presentation with embedded Data Integrity or secp256k1 proof. Proofs are appended to the
 * proof set, never replaced.
 */
public class JSONPresentation implements Presentation {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private PresentationData presentationData;

    private JSONPresentation() {
    }

    public static JSONPresentation create(PresentationContents vpc) throws Exception {
        return create(vpc, null);
    }

    public static JSONPresentation create(PresentationContents vpc, PresentationOptions opts) throws Exception {
        JSONPresentation pres = new JSONPresentation();
        pres.presentationData = PresentationHelper.serializePresentationContents(vpc);
        pres.executeOptions(PresentationOptions.orEmpty(opts));
        return pres;
    }

    public static JSONPresentation newJSONPresentation(PresentationContents vpc, PresentationOptions opts)
            throws Exception {
        return create(vpc, opts);
    }

    public static JSONPresentation parseJSONPresentation(byte[] rawJSON, PresentationOptions opts) throws Exception {
        return parse(rawJSON, opts);
    }

    public static JSONPresentation parse(byte[] rawJSON) throws Exception {
        return parse(rawJSON, null);
    }

    public static JSONPresentation parse(byte[] rawJSON, PresentationOptions opts) throws Exception {
        if (rawJSON == null || rawJSON.length == 0) {
            throw new Exception("JSON string is empty");
        }
        Map<String, Object> map;
        try {
            map = MAPPER.readValue(rawJSON, new TypeReference<Map<String, Object>>() {
            });
        } catch (Exception e) {
            throw new Exception("invalid JSON format", e);
        }
        if (map == null) {
            throw new Exception("invalid JSON format");
        }
        JSONPresentation pres = new JSONPresentation();
        pres.presentationData = new PresentationData(map);
        pres.executeOptions(PresentationOptions.orEmpty(opts));
        return pres;
    }

    /** Signs with a raw P-256 private key (hex scalar), like Go {@code AddProof}. Prefer a provider. */
    public void addProof(String privKeyHex) throws Exception {
        addProof(privKeyHex, null);
    }

    public void addProof(String privKeyHex, PresentationOptions opts) throws Exception {
        addProofByProvider(new P256SignerProvider(privKeyHex), opts);
    }

    /** Signs with a raw secp256k1 private key (hex); the VM must hold a secp256k1 key. */
    public void addProofSecp256k1(String privKeyHex, PresentationOptions opts) throws Exception {
        addProofByProvider(new DefaultSignerProvider(privKeyHex), opts);
    }

    public void addProofByProvider(SignerProvider signerProvider) throws Exception {
        addProofByProvider(signerProvider, null);
    }

    /**
     * Signs bound to the holder VM {@code withVerificationMethodKey} pins (default: latest active authentication
     * VM). {@code withChallenge} / {@code withDomain} go on the proof. Proofs are appended;
     * {@code withReplaceProof} is refused.
     */
    public void addProofByProvider(SignerProvider signerProvider, PresentationOptions opts) throws Exception {
        if (signerProvider == null) {
            throw new IllegalArgumentException("signer provider cannot be null");
        }
        PresentationOptions o = PresentationOptions.orEmpty(opts);
        refuseReplaceOnJSONLD(o);
        executeOptions(o.forSigning());

        String holder = Vcdm.didFromField(presentationData.get("holder"));
        if (holder == null) {
            throw new Exception("holder is missing or invalid");
        }
        CredentialResolver resolver = o.effectiveResolver();
        var signing = ResolveVmUrl.resolveSigningVM(holder, "authentication", o.getVerificationMethodKey(), resolver);
        VerificationMethodEntry vm = signing.vm();
        String vmURL = signing.url();
        VerificationMethodKeyKind kind = VerificationMethodKeyKind.fromEntry(vm);
        if (kind != VerificationMethodKeyKind.SECP256K1 && kind != VerificationMethodKeyKind.P256) {
            throw new Exception("verification method " + vmURL + " has an unrecognized key type");
        }
        PublicKey vmPub = resolver.ecPublicKeyFromEntry(vm);

        if (kind == VerificationMethodKeyKind.SECP256K1) {
            presentationData.addEcdsaSecp256k1ProofByProvider(signerProvider, vmURL, "authentication", null, vmPub,
                    o.getChallenge(), o.getDomain());
        } else {
            presentationData.addECDSAProofByProvider(signerProvider, vmURL, "authentication", null, vmPub,
                    o.getChallenge(), o.getDomain());
        }
    }

    /** SHA-256 of the canonicalized document body (library canonicalizer); feed it to {@link #createProofSigning}. */
    public byte[] getSigningInput() throws Exception {
        return presentationData.getDocumentDigest();
    }

    /** The 32-byte digest an external signer signs: SHA-256 of the hashData built from docHash and the proof. */
    public byte[] createProofSigning(byte[] docHash, Proof proof) throws Exception {
        return presentationData.createProofSigning(docHash, proof);
    }

    public void addCustomProof(Proof proof) throws Exception {
        addCustomProof(proof, null);
    }

    /**
     * Attaches a proof signed outside the SDK. challenge, domain and the VM key are part of the proof and cannot
     * be set here. With {@code withVerifyProof} only the incoming proof is checked (ecdsa-rdfc-2019 only).
     */
    public void addCustomProof(Proof proof, PresentationOptions opts) throws Exception {
        if (proof == null) {
            throw new IllegalArgumentException("proof cannot be null");
        }
        PresentationOptions o = PresentationOptions.orEmpty(opts);
        refuseReplaceOnJSONLD(o);
        if (nonEmpty(o.getChallenge()) || nonEmpty(o.getDomain()) || nonEmpty(o.getVerificationMethodKey())) {
            throw new Exception("withChallenge / withDomain / withVerificationMethodKey cannot be applied by "
                    + "addCustomProof: set proof.challenge, proof.domain and proof.verificationMethod on the proof "
                    + "you sign");
        }
        if (o.isVerifyProof()) {
            presentationData.verifyDetachedProof(o.effectiveResolver(), proof);
        }
        executeOptions(o.forSigning());
        presentationData.addCustomProof(proof);
    }

    @Override
    public void verify(PresentationOptions opts) throws Exception {
        PresentationOptions o = PresentationOptions.orEmpty(opts).copy();
        o.setVerifyProof(true);
        executeOptions(o);
    }

    @Override
    public Map<String, Object> serialize() throws Exception {
        if (presentationData.get("proof") == null) {
            throw new Exception("presentation must have proof before serialization");
        }
        return presentationData.toMap();
    }

    @Override
    public byte[] getContents() throws Exception {
        return presentationData.toJSON();
    }

    @Override
    public String getType() {
        return "JSON";
    }

    @Override
    public Object extractField(String path) {
        return Vcdm.extractField(presentationData, path);
    }

    public PresentationData getPresentationData() {
        return presentationData;
    }

    private void executeOptions(PresentationOptions o) throws Exception {
        if (o.isValidateVC()) {
            PresentationHelper.verifyEmbeddedCredentials(presentationData, o);
        }
        if (o.isCheckExpiration()) {
            try {
                PresentationHelper.checkExpiration(presentationData, o.getClockSkewLeewayMs());
            } catch (CredentialException e) {
                throw e;
            } catch (Exception e) {
                throw new Exception("failed to check expiration: " + e.getMessage(), e);
            }
        }
        if (o.isVerifyProof()) {
            boolean ok;
            try {
                ok = presentationData.verifyProof(o.effectiveResolver(), o.getProofVerificationMethod());
            } catch (Exception e) {
                throw new Exception("failed to verify presentation: " + e.getMessage(), e);
            }
            if (!ok) {
                throw new CredentialException(CredentialException.Code.INVALID_PROOF, "invalid proof");
            }
            // Only meaningful against the proofs verifyProof just validated: a challenge/domain that is not bound
            // to a verified signature proves nothing about who the presentation was made for.
            checkChallengeAndDomain(o);
        }
    }

    // Enforces expectedChallenge / expectedDomain on EVERY verified proof (or only the proofVerificationMethod
    // one), so a replayed proof cannot hide among others.
    private void checkChallengeAndDomain(PresentationOptions o) throws Exception {
        String expChallenge = o.getExpectedChallenge();
        String expDomain = o.getExpectedDomain();
        if (o.isRequireAudience() && !nonEmpty(expDomain)) {
            throw new AudienceUnboundException();
        }
        if (!nonEmpty(expChallenge) && !nonEmpty(expDomain)) {
            return;
        }
        String only = o.getProofVerificationMethod();
        for (Proof p : presentationData.proofs()) {
            if (nonEmpty(only) && !only.equals(p.getVerificationMethod())) {
                continue;
            }
            Object domain = p.getRaw() != null ? p.getRaw().get("domain") : p.getDomain();
            if (nonEmpty(expChallenge) && !expChallenge.equals(p.getChallenge() == null ? "" : p.getChallenge())) {
                throw new CredentialException(CredentialException.Code.INVALID_PROOF,
                        "failed to verify presentation: proof (" + p.getVerificationMethod() + "): challenge "
                                + p.getChallenge() + " does not match expected " + expChallenge);
            }
            if (nonEmpty(expDomain) && !PresentationAudience.audContains(domain, expDomain)) {
                throw new CredentialException(CredentialException.Code.INVALID_PROOF,
                        "failed to verify presentation: proof (" + p.getVerificationMethod() + "): domain " + domain
                                + " does not match expected " + expDomain);
            }
        }
    }

    private static void refuseReplaceOnJSONLD(PresentationOptions o) throws CredentialException {
        if (o.isReplaceProof()) {
            throw new CredentialException(CredentialException.Code.UNSUPPORTED_OPTION,
                    "withReplaceProof does not apply to JSON-LD: proofs are appended to the proof set, not replaced; "
                            + "build a new presentation without the proof to re-sign");
        }
    }

    private static boolean nonEmpty(String s) {
        return s != null && !s.isEmpty();
    }
}
