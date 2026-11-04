package com.pila.credential.vp;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.dto.Proof;
import com.pila.credential.common.signer.DefaultSignerProvider;
import com.pila.credential.common.signer.SignerProvider;
import com.pila.credential.common.verificationmethod.CredentialResolver;
import com.pila.credential.common.verificationmethod.VerificationMethodEntry;
import com.pila.credential.common.verificationmethod.VerificationMethodKeyKind;
import com.pila.credential.vc.CredentialConfig;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Map;

/**
 * JSON-LD verifiable presentation with embedded Data Integrity or secp256k1 proof.
 */
public class JSONPresentation {
    private static final String DEFAULT_VERIFICATION_METHOD_KEY = "key-1";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private PresentationData presentationData;
    private String verificationMethodKey;

    private JSONPresentation() {
        this.verificationMethodKey = DEFAULT_VERIFICATION_METHOD_KEY;
    }

    public static JSONPresentation create(PresentationContents vpc) throws Exception {
        return create(vpc, null);
    }

    public static JSONPresentation create(PresentationContents vpc, PresentationOptions opts) throws Exception {
        PresentationData m = PresentationHelper.serializePresentationContents(vpc);
        JSONPresentation pres = new JSONPresentation();
        pres.presentationData = m;
        if (opts != null && opts.getVerificationMethodKey() != null) {
            pres.verificationMethodKey = opts.getVerificationMethodKey();
        }
        pres.executeOptions(opts);
        return pres;
    }

    public static JSONPresentation parse(byte[] rawJSON) throws Exception {
        return parse(rawJSON, null);
    }

    public static JSONPresentation parse(byte[] rawJSON, PresentationOptions opts) throws Exception {
        if (rawJSON == null || rawJSON.length == 0) {
            throw new Exception("JSON string is empty");
        }
        Map<String, Object> map = MAPPER.readValue(rawJSON, new TypeReference<Map<String, Object>>() {
        });
        if (map == null) {
            throw new Exception("invalid JSON format");
        }
        JSONPresentation pres = new JSONPresentation();
        pres.presentationData = new PresentationData(map);
        pres.executeOptions(opts);
        return pres;
    }

    public void addProof(String privKeyHex) throws Exception {
        addProofByProvider(new DefaultSignerProvider(privKeyHex));
    }

    public void addProof(String privKeyHex, PresentationOptions opts) throws Exception {
        addProofByProvider(new DefaultSignerProvider(privKeyHex), opts);
    }

    public void addProofByProvider(SignerProvider signerProvider) throws Exception {
        addProofByProvider(signerProvider, null);
    }

    public void addProofByProvider(SignerProvider signerProvider, PresentationOptions opts) throws Exception {
        if (signerProvider == null) {
            throw new IllegalArgumentException("signer provider cannot be null");
        }
        executeOptions(opts);
        Object holderObj = presentationData.get("holder");
        if (!(holderObj instanceof String holder) || holder.isEmpty()) {
            throw new Exception("holder is missing or invalid");
        }
        PresentationOptions options = opts != null ? opts : new PresentationOptions();
        String vmKey = verificationMethodKey;
        if (options.getVerificationMethodKey() != null && !options.getVerificationMethodKey().isEmpty()) {
            vmKey = options.getVerificationMethodKey();
        }
        CredentialResolver resolver = options.getResolver() != null
                ? options.getResolver()
                : CredentialConfig.getDocumentResolver();
        var signing = com.pila.credential.common.verificationmethod.ResolveVmUrl.resolveSigningVM(
                holder, "authentication", vmKey, resolver);
        VerificationMethodEntry vm = signing.vm();
        String vmURL = signing.url();
        VerificationMethodKeyKind kind = VerificationMethodKeyKind.fromEntry(vm);
        PublicKey vmPub = resolver.ecPublicKeyFromEntry(vm);
        String didBaseURL = CredentialConfig.getBaseURL();

        if (presentationData.get("proof") != null && !options.isReplaceProof()) {
            throw new Exception("presentation already has a proof; pass WithReplaceProof to replace it");
        }
        if (kind == VerificationMethodKeyKind.SECP256K1) {
            presentationData.addEcdsaSecp256k1ProofByProvider(
                    signerProvider, vmURL, "authentication", didBaseURL, vmPub,
                    options.getChallenge(), options.getDomain());
        } else if (kind == VerificationMethodKeyKind.P256) {
            presentationData.addECDSAProofByProvider(
                    signerProvider,
                    vmURL,
                    "authentication",
                    didBaseURL,
                    vmPub,
                    options.getChallenge(),
                    options.getDomain());
        } else {
            throw new Exception("verification method " + vmURL + " has an unrecognized key type");
        }
    }

    public byte[] getSigningInput() throws Exception {
        return presentationData.canonicalize();
    }

    public void addCustomProof(Proof proof, PresentationOptions opts) throws Exception {
        if (proof == null) {
            throw new IllegalArgumentException("proof cannot be null");
        }
        PresentationOptions merged = opts != null ? opts : new PresentationOptions();
        if (!merged.isVerifyProof() && presentationData.get("proof") != null) {
            merged.setVerifyProof(true);
        }
        executeOptions(merged);
        presentationData.addCustomProof(proof);
    }

    public void verify() throws Exception {
        verify(null);
    }

    public void verify(PresentationOptions opts) throws Exception {
        PresentationOptions merged = opts != null ? opts : new PresentationOptions();
        merged.setVerifyProof(true);
        executeOptions(merged);
    }

    public Map<String, Object> serialize() throws Exception {
        if (presentationData.get("proof") == null) {
            throw new Exception("presentation must have proof before serialization");
        }
        return presentationData.toMap();
    }

    public byte[] getContents() throws Exception {
        return presentationData.toJSON();
    }

    public PresentationData getPresentationData() {
        return presentationData;
    }

    public void setVerificationMethodKey(String verificationMethodKey) {
        if (verificationMethodKey != null && !verificationMethodKey.isEmpty()) {
            this.verificationMethodKey = verificationMethodKey;
        }
    }

    public void executeOptions(PresentationOptions opts) throws Exception {
        if (opts == null) {
            return;
        }
        if (opts.isValidateVC()) {
            PresentationHelper.verifyEmbeddedCredentials(presentationData);
        }
        if (opts.isVerifyProof()) {
            CredentialResolver resolver = opts.getResolver() != null
                    ? opts.getResolver()
                    : (opts.getDidBaseURL() != null && !opts.getDidBaseURL().isEmpty()
                            ? CredentialConfig.resolverFor(opts.getDidBaseURL())
                            : CredentialConfig.getDocumentResolver());
            boolean ok = presentationData.verifyProof(resolver, opts.getProofVerificationMethod());
            if (!ok) {
                throw new Exception("invalid proof");
            }
            // Only meaningful against the proofs VerifyProof just validated: a
            // challenge/domain that is not bound to a verified signature proves
            // nothing about who the presentation was made for.
            checkChallengeAndDomain(opts);
        }
        if (opts.isCheckExpiration()) {
            PresentationHelper.checkExpiration(presentationData, opts.getClockSkewLeewayMs());
        }
    }

    // Enforces expectedChallenge / expectedDomain on EVERY verified proof (or only
    // the proofVerificationMethod one), so a replayed proof cannot hide among
    // others. Mirrors go-credential-sdk JSONPresentation.checkChallengeAndDomain.
    private void checkChallengeAndDomain(PresentationOptions opts) throws Exception {
        String expChallenge = opts.getExpectedChallenge();
        String expDomain = opts.getExpectedDomain();
        if (opts.isRequireAudience() && (expDomain == null || expDomain.isEmpty())) {
            throw new Exception("WithRequireAudience needs WithExpectedDomain");
        }
        boolean hasChallenge = expChallenge != null && !expChallenge.isEmpty();
        boolean hasDomain = expDomain != null && !expDomain.isEmpty();
        if (!hasChallenge && !hasDomain) {
            return;
        }
        String only = opts.getProofVerificationMethod();
        for (Proof p : allProofs()) {
            if (only != null && !only.isEmpty() && !only.equals(p.getVerificationMethod())) {
                continue;
            }
            if (hasChallenge && !expChallenge.equals(p.getChallenge())) {
                throw new Exception("proof (" + p.getVerificationMethod() + "): challenge " + p.getChallenge()
                        + " does not match expected " + expChallenge);
            }
            if (hasDomain && !PresentationAudience.audContains(p.getDomain(), expDomain)) {
                throw new Exception("proof (" + p.getVerificationMethod() + "): domain " + p.getDomain()
                        + " does not match expected " + expDomain);
            }
        }
    }

    private java.util.List<Proof> allProofs() {
        java.util.List<Proof> proofs = new java.util.ArrayList<>();
        Object raw = presentationData.get("proof");
        if (raw instanceof Map<?, ?> map) {
            proofs.add(MAPPER.convertValue(map, Proof.class));
        } else if (raw instanceof Iterable<?> list) {
            for (Object item : list) {
                if (item instanceof Map<?, ?>) {
                    proofs.add(MAPPER.convertValue(item, Proof.class));
                }
            }
        }
        return proofs;
    }
}
