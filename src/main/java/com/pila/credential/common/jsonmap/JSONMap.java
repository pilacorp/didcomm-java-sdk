package com.pila.credential.common.jsonmap;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.crypto.Crypto;
import com.pila.credential.common.dto.Proof;
import com.pila.credential.common.ecdsasd.EcdsaSd;
import com.pila.credential.common.processor.Processor;
import com.pila.credential.common.signer.DefaultSignerProvider;
import com.pila.credential.common.signer.SignerProvider;
import com.pila.credential.common.util.Multibase;
import com.pila.credential.common.util.VCUtil;
import com.pila.credential.common.verificationmethod.ChainingCredentialResolver;
import com.pila.credential.common.verificationmethod.CredentialResolver;
import com.pila.credential.common.verificationmethod.DIDDocument;
import com.pila.credential.common.verificationmethod.DidKeyP256Resolver;
import com.pila.credential.common.verificationmethod.StrictPurposeCheck;
import com.pila.credential.common.verificationmethod.VerificationMethodEntry;
import com.pila.credential.common.verificationmethod.VerificationMethodKeyKind;
import com.pila.credential.common.verificationmethod.VerificationMethodMaterial;
import com.pila.credential.common.verificationmethod.VerificationMethodResolver;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.*;

/**
 * JSONMap represents a JSON object as a map.
 * This class provides methods for serialization, canonicalization, proof
 * management, and verification.
 */
public class JSONMap extends HashMap<String, Object> {

    // Constants for proof types
    public static final String JWT_PROOF_2020 = "JwtProof2020";
    public static final String ECDSA_SECP256K1_SIGNATURE_2019 = "EcdsaSecp256k1Signature2019";
    public static final String DATA_INTEGRITY_PROOF = "DataIntegrityProof";
    public static final String ECDSA_RDFC_2019 = "ecdsa-rdfc-2019";
    public static final String ECDSA_SD_2023 = "ecdsa-sd-2023";
    public static final String ECDSA_SECP_KEY = "EcdsaSecp256k1VerificationKey2019";
    public static final String JSON_WEB_SIGNATURE_2020 = "JsonWebSignature2020";
    public static final String JSON_WEB_KEY_2020 = "JsonWebKey2020";
    private static final String DATA_INTEGRITY_V2_CONTEXT = "https://w3id.org/security/data-integrity/v2";
    private static final String SECP256K1_SUITE_CONTEXT = "https://w3id.org/security/suites/secp256k1-2019/v1";
    private static final String ALG_ES256K = "ES256K";

    private static final ObjectMapper objectMapper = new ObjectMapper();

    public JSONMap() {
        super();
    }

    public JSONMap(Map<? extends String, ?> m) {
        super(m);
    }

    /**
     * Serializes the JSONMap to JSON bytes.
     * 
     * @return JSON bytes
     * @throws Exception if serialization fails
     */
    public byte[] toJSON() throws Exception {
        try {
            byte[] data = objectMapper.writeValueAsBytes(this);

            // Validate serialization by deserializing
            JSONMap temp = objectMapper.readValue(data, JSONMap.class);
            if (temp == null) {
                throw new Exception("failed to validate serialization: deserialized map is null");
            }

            return data;
        } catch (Exception e) {
            throw new Exception("failed to marshal JSONMap: " + e.getMessage(), e);
        }
    }

    /**
     * Converts the JSONMap to a standard Map.
     * 
     * @return A Map representation
     * @throws Exception if conversion fails
     */
    public Map<String, Object> toMap() throws Exception {
        try {
            byte[] bytes = objectMapper.writeValueAsBytes(this);

            Map<String, Object> data = objectMapper.readValue(bytes,
                    new TypeReference<Map<String, Object>>() {
                    });
            return data;
        } catch (Exception e) {
            throw new Exception("failed to marshal JSONMap: " + e.getMessage(), e);
        }
    }

    /**
     * Canonicalizes the JSONMap for signing or verification, excluding the proof
     * field.
     * 
     * @return The canonicalized and digested bytes
     * @throws Exception if canonicalization fails
     */
    public byte[] canonicalize() throws Exception {
        JSONMap mCopy = new JSONMap();
        for (Map.Entry<String, Object> entry : this.entrySet()) {
            if (!"proof".equals(entry.getKey())) {
                mCopy.put(entry.getKey(), entry.getValue());
            }
        }

        try {
            byte[] encoded = objectMapper.writeValueAsBytes(mCopy);
            Map<String, Object> doc = objectMapper.readValue(encoded, new TypeReference<Map<String, Object>>() {
            });

            byte[] canonicalDoc = Processor.canonicalizeDocument(doc);
            return Processor.computeDigest(canonicalDoc);
        } catch (Exception e) {
            throw new Exception("failed to canonicalize JSONMap: " + e.getMessage(), e);
        }
    }

    /**
     * Adds a DataIntegrityProof (ecdsa-rdfc-2019) using a signing provider.
     */
    public void addECDSAProofByProvider(SignerProvider signerProvider,
            String verificationMethod,
            String proofPurpose) throws Exception {
        addECDSAProofByProvider(signerProvider, verificationMethod, proofPurpose, null, null);
    }

    public void addECDSAProofByProvider(SignerProvider signerProvider,
            String verificationMethod,
            String proofPurpose,
            String didBaseURL) throws Exception {
        addECDSAProofByProvider(signerProvider, verificationMethod, proofPurpose, didBaseURL, null);
    }

    public void addECDSAProofByProvider(SignerProvider signerProvider,
            String verificationMethod,
            String proofPurpose,
            String didBaseURL,
            PublicKey vmPublicKey) throws Exception {
        addECDSAProofByProvider(signerProvider, verificationMethod, proofPurpose, didBaseURL, vmPublicKey, null, null);
    }

    public void addECDSAProofByProvider(SignerProvider signerProvider,
            String verificationMethod,
            String proofPurpose,
            String didBaseURL,
            PublicKey vmPublicKey,
            String challenge,
            String domain) throws Exception {
        if (signerProvider == null) {
            throw new IllegalArgumentException("signerProvider cannot be null");
        }
        requireVmAndPurpose(verificationMethod, proofPurpose);
        Object contextBackup = snapshotContext();
        try {
            ensureDataIntegrityContext();

            Proof proof = new Proof();
            proof.setType(DATA_INTEGRITY_PROOF);
            proof.setCreated(com.pila.credential.common.util.Rfc3339.now());
            proof.setVerificationMethod(verificationMethod);
            proof.setProofPurpose(proofPurpose);
            proof.setCryptosuite(ECDSA_RDFC_2019);
            if (challenge != null && !challenge.isEmpty()) {
                proof.setChallenge(challenge);
            }
            if (domain != null && !domain.isEmpty()) {
                proof.setDomain(domain);
            }

            byte[] hashData = ecdsaHashData(proof);
            byte[] signDigest = sha256(hashData);
            byte[] signature = signerProvider.sign(signDigest);
            if (signature.length != 64) {
                throw new IllegalArgumentException(
                        "ecdsa-rdfc-2019 expects a 64-byte P-256 signature (r||s) but got " + signature.length);
            }
            if (vmPublicKey != null && !Crypto.verifyEcdsaRaw(vmPublicKey, signDigest, signature)) {
                throw new Exception("signature verification failed against verification method");
            }

            proof.setProofValue(Multibase.encodeBase58Btc(signature));
            appendProof(proof);
        } catch (Exception e) {
            restoreContext(contextBackup);
            throw e;
        }
    }

    /**
     * Adds an EcdsaSecp256k1Signature2019 proof (detached JWS, ES256K).
     */
    public void addEcdsaSecp256k1ProofByProvider(SignerProvider signerProvider,
            String verificationMethod,
            String proofPurpose,
            String didBaseURL,
            PublicKey vmPublicKey) throws Exception {
        addEcdsaSecp256k1ProofByProvider(signerProvider, verificationMethod, proofPurpose, didBaseURL, vmPublicKey,
                null, null);
    }

    public void addEcdsaSecp256k1ProofByProvider(SignerProvider signerProvider,
            String verificationMethod,
            String proofPurpose,
            String didBaseURL,
            PublicKey vmPublicKey,
            String challenge,
            String domain) throws Exception {
        if (signerProvider == null) {
            throw new IllegalArgumentException("signerProvider cannot be null");
        }
        requireVmAndPurpose(verificationMethod, proofPurpose);
        requireSecp256k1Key(vmPublicKey);
        Object contextBackup = snapshotContext();
        try {
            ensureSecp256k1SuiteContext();

            Proof proof = new Proof();
            proof.setType(ECDSA_SECP256K1_SIGNATURE_2019);
            proof.setCreated(com.pila.credential.common.util.Rfc3339.now());
            proof.setVerificationMethod(verificationMethod);
            proof.setProofPurpose(proofPurpose);
            if (challenge != null && !challenge.isEmpty()) {
                proof.setChallenge(challenge);
            }
            if (domain != null && !domain.isEmpty()) {
                proof.setDomain(domain);
            }

            String encHeader = JwsDetached.encodeHeader(ALG_ES256K);
            byte[] hashData = ecdsaHashData(proof);
            byte[] signingInput = JwsDetached.signingInput(encHeader, hashData);
            byte[] signDigest = sha256(signingInput);
            byte[] signature = signerProvider.sign(signDigest);
            if (signature.length == 65) {
                signature = Arrays.copyOf(signature, 64);
            }
            if (signature.length != 64) {
                throw new IllegalArgumentException("EcdsaSecp256k1Signature2019 expects 64-byte r||s signature");
            }
            signature = normalizeLowS(signature);
            if (vmPublicKey != null && !Crypto.verifyEcdsaRaw(vmPublicKey, signDigest, signature)) {
                throw new Exception("signature verification failed against verification method");
            }

            String encSig = Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
            proof.setJws(encHeader + ".." + encSig);
            appendProof(proof);
        } catch (Exception e) {
            restoreContext(contextBackup);
            throw e;
        }
    }


    /**
     * SHA-256 digest of the canonical document body (without proof). External signing entry point.
     */
    public byte[] getDocumentDigest() throws Exception {
        return documentDigest();
    }

    /**
     * Returns the 32-byte digest the external signer signs: SHA-256 of the section 3.2.4 hashData built from the
     * document digest and the proof options.
     */
    public byte[] createProofSigning(byte[] docHash, Proof proof) throws Exception {
        return sha256(proofHashData(docHash, proof));
    }

    /**
     * Adds a custom proof to the JSONMap.
     */
    public void addCustomProof(Proof proof) throws Exception {
        if (proof == null) {
            throw new IllegalArgumentException("proof is null");
        }
        if (DATA_INTEGRITY_PROOF.equals(proof.getType()) && ECDSA_RDFC_2019.equals(proof.getCryptosuite())
                && (proof.getProofValue() == null || !proof.getProofValue().startsWith("z"))) {
            throw new Exception("proofValue must be multibase base58btc (\"z\" prefix); hex proofs are no longer issued");
        }
        appendProof(proof);
    }

    /**
     * Verifies one proof against the document as it stands, before that proof is attached, so a proof signed over
     * the wrong digest or by the wrong key fails where it is added. Only ecdsa-rdfc-2019 can be checked this way
     * (the other suites bind to something the document does not carry yet). The document is not modified.
     */
    public void verifyDetachedProof(CredentialResolver resolver, Proof proof) throws Exception {
        if (proof == null) {
            throw new IllegalArgumentException("proof is null");
        }
        if (resolver == null) {
            throw new IllegalArgumentException("document resolver is required");
        }
        if (!DATA_INTEGRITY_PROOF.equals(proof.getType()) || !ECDSA_RDFC_2019.equals(proof.getCryptosuite())) {
            throw new Exception("a " + proof.getType() + (proof.getCryptosuite() != null ? "/" + proof.getCryptosuite() : "")
                    + " proof cannot be checked before it is attached; only " + DATA_INTEGRITY_PROOF + "/"
                    + ECDSA_RDFC_2019 + " can — attach it without withVerifyProof and call verify instead");
        }
        boolean ok = verifyOneProof(resolver, proof);
        if (!ok) {
            throw new Exception("the proof does not verify against verification method "
                    + proof.getVerificationMethod() + "; it was signed by another key or over data other than this document");
        }
    }

    /** Parsed view of every proof in the set (does not change what is stored). */
    public List<Proof> proofs() throws Exception {
        List<Proof> out = new ArrayList<>();
        for (Object raw : rawProofList()) {
            out.add(parseRawToProof(raw));
        }
        return out;
    }

    /** True when the first proof carries a multibase proofValue (base58btc "z" / base64url "u"). */
    public boolean hasMultibaseProof() {
        List<Object> list = rawProofList();
        if (list.isEmpty() || !(list.get(0) instanceof Map<?, ?> p) || !(p.get("proofValue") instanceof String pv)) {
            return false;
        }
        return pv.startsWith("z") || pv.startsWith("u");
    }

    /** Legacy canonicalizer over the whole map including proof (Go {@code CanonicalizeFull}); the identity of a legacy VC. */
    public byte[] canonicalizeFull() throws Exception {
        try {
            Map<String, Object> doc = objectMapper.readValue(objectMapper.writeValueAsBytes(this),
                    new TypeReference<Map<String, Object>>() {
                    });
            return Processor.computeDigest(Processor.canonicalizeDocument(doc));
        } catch (Exception e) {
            throw new Exception("failed to canonicalize document: " + e.getMessage(), e);
        }
    }

    /** Library canonicalizer (Go {@code processor.Canonicalize}) over the whole map including proof, SHA-256. */
    public byte[] canonicalizeFullNativeTypes() throws Exception {
        Map<String, Object> doc = objectMapper.readValue(objectMapper.writeValueAsBytes(this),
                new TypeReference<Map<String, Object>>() {
                });
        return Processor.computeDigest(Processor.canonicalizeDocumentNativeTypes(doc));
    }

    /**
     * Parses a raw proof object into a Proof struct.
     */
    public static Proof parseRawToProof(Object proof) throws Exception {
        Proof result = new Proof();

        if (!(proof instanceof Map)) {
            throw new IllegalArgumentException(
                    "invalid proof format: expected Map, got " + (proof != null ? proof.getClass().getName() : "null"));
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> proofMap = (Map<String, Object>) proof;
        result.setRaw(new LinkedHashMap<>(proofMap));

        if (proofMap.containsKey("type") && proofMap.get("type") instanceof String) {
            result.setType((String) proofMap.get("type"));
        }
        if (proofMap.containsKey("created") && proofMap.get("created") instanceof String) {
            result.setCreated((String) proofMap.get("created"));
        }
        if (proofMap.containsKey("proofPurpose") && proofMap.get("proofPurpose") instanceof String) {
            result.setProofPurpose((String) proofMap.get("proofPurpose"));
        }
        if (proofMap.containsKey("verificationMethod") && proofMap.get("verificationMethod") instanceof String) {
            result.setVerificationMethod((String) proofMap.get("verificationMethod"));
        }
        if (proofMap.containsKey("proofValue") && proofMap.get("proofValue") instanceof String) {
            result.setProofValue((String) proofMap.get("proofValue"));
        }
        if (proofMap.containsKey("cryptosuite") && proofMap.get("cryptosuite") instanceof String) {
            result.setCryptosuite((String) proofMap.get("cryptosuite"));
        }
        if (proofMap.containsKey("jws") && proofMap.get("jws") instanceof String) {
            result.setJws((String) proofMap.get("jws"));
        }
        if (proofMap.containsKey("challenge") && proofMap.get("challenge") instanceof String) {
            result.setChallenge((String) proofMap.get("challenge"));
        }
        if (proofMap.containsKey("domain") && proofMap.get("domain") instanceof String) {
            result.setDomain((String) proofMap.get("domain"));
        }

        return result;
    }

    /**
     * Verifies an ECDSA-signed JSONMap.
     */
    public boolean verifyProof(String didBaseURL) throws Exception {
        // Default resolver is HTTP only (Go NewHTTPResolver); offline did:key is opt-in via an injected resolver.
        return verifyProof(new VerificationMethodResolver(didBaseURL));
    }

    /**
     * Verifies proofs using an injected DID resolver (offline or HTTP).
     */
    public boolean verifyProof(CredentialResolver resolver) throws Exception {
        return verifyProof(resolver, null);
    }

    public boolean verifyProof(CredentialResolver resolver, String proofVerificationMethod) throws Exception {
        Object proofObj = this.get("proof");
        if (proofObj == null) {
            throw new Exception("JSONMap has no proof");
        }

        List<Object> proofs;
        if (proofObj instanceof List) {
            @SuppressWarnings("unchecked")
            List<Object> proofList = (List<Object>) proofObj;
            proofs = proofList;
        } else {
            proofs = new ArrayList<>();
            proofs.add(proofObj);
        }

        if (proofs.isEmpty()) {
            throw new Exception("JSONMap has no proof");
        }

        boolean matched = proofVerificationMethod == null || proofVerificationMethod.isEmpty();
        for (Object raw : proofs) {
            Proof proof = parseRawToProof(raw);
            if (proofVerificationMethod != null && !proofVerificationMethod.isEmpty()) {
                if (!proofVerificationMethod.equals(proof.getVerificationMethod())) {
                    continue;
                }
                matched = true;
            }
            if (!verifyOneProof(resolver, proof)) {
                return false;
            }
        }
        if (!matched) {
            throw new Exception("no proof bound to verification method " + proofVerificationMethod);
        }
        return true;
    }

    private boolean verifyOneProof(CredentialResolver resolver, Proof proof) throws Exception {
        if (JWT_PROOF_2020.equals(proof.getType())) {
            return verifyJwtProof2020(resolver, proof);
        }
        if (JSON_WEB_SIGNATURE_2020.equals(proof.getType())) {
            return verifyJwsProof(resolver, proof);
        }
        if (ECDSA_SECP256K1_SIGNATURE_2019.equals(proof.getType())) {
            return verifyEcdsaSecp256k1Proof(resolver, proof);
        }
        if (DATA_INTEGRITY_PROOF.equals(proof.getType()) && ECDSA_RDFC_2019.equals(proof.getCryptosuite())) {
            VerificationMethodEntry vmEntry = resolver.findVerificationMethod(proof.getVerificationMethod());
            String didPart = didFromVerificationMethod(proof.getVerificationMethod());
            DIDDocument doc = resolver.resolveDocument(didPart);
            PublicKey publicKey = resolver.ecPublicKeyFromEntry(vmEntry);
            if (!verifyECDSA(publicKey, proof)) {
                return false;
            }
            StrictPurposeCheck.enforce(doc, vmEntry, proof.getProofPurpose(), proof.getCreated());
            return true;
        }
        if (DATA_INTEGRITY_PROOF.equals(proof.getType()) && ECDSA_SD_2023.equals(proof.getCryptosuite())) {
            return verifyEcdsaSdProof(resolver, proof);
        }
        throw new Exception("unsupported proof type: " + proof.getType());
    }

    /**
     * JwtProof2020 (legacy): the verification method comes from the proof (or the kid of its jws), the
     * key from that method in the signer's DID document, and {@code proof.jwt} is checked against it.
     */
    private boolean verifyJwtProof2020(CredentialResolver resolver, Proof proof) throws Exception {
        String vmUrl = jwtVerificationMethodUrl(proof);
        String didPart = didFromVerificationMethod(vmUrl);
        DIDDocument doc = resolver.resolveDocument(didPart);
        VerificationMethodEntry vm = resolver.findVerificationMethod(vmUrl);
        PublicKey publicKey = resolver.ecPublicKeyFromEntry(vm);
        Map<String, Object> req = new HashMap<>();
        req.put("proof", proof.getRaw() != null ? proof.getRaw() : Map.of());
        if (!Crypto.verifyJwtProof(req, publicKey)) {
            return false;
        }
        StrictPurposeCheck.enforce(doc, vm, "assertionMethod", proof.getCreated());
        return true;
    }

    private static String jwtVerificationMethodUrl(Proof proof) throws Exception {
        if (proof.getVerificationMethod() != null && !proof.getVerificationMethod().isEmpty()) {
            return proof.getVerificationMethod();
        }
        String jws = proof.getJws();
        int dot = jws == null ? -1 : jws.indexOf('.');
        if (dot > 0) {
            try {
                Object kid = objectMapper.readValue(Base64.getUrlDecoder().decode(jws.substring(0, dot)),
                        new TypeReference<Map<String, Object>>() {
                        }).get("kid");
                if (kid instanceof String k && !k.isEmpty()) {
                    return k;
                }
            } catch (Exception ignored) {
                // fall through to the missing-kid error
            }
        }
        throw new Exception("token is missing verification method id (kid/verificationMethod)");
    }

    /**
     * JsonWebSignature2020 (legacy): detached JWS with b64:false over {@code header.digest}, where the
     * digest is the legacy document digest; ES256 against a P-256 JWK, RS/PS 256/384/512 against an RSA JWK.
     */
    private boolean verifyJwsProof(CredentialResolver resolver, Proof proof) throws Exception {
        String didPart = didFromVerificationMethod(proof.getVerificationMethod());
        DIDDocument doc = resolver.resolveDocument(didPart);
        VerificationMethodEntry vm = resolver.findVerificationMethod(proof.getVerificationMethod());
        if (!JSON_WEB_KEY_2020.equals(vm.getType())) {
            throw new Exception("expected " + JSON_WEB_KEY_2020 + " VM, got " + vm.getType());
        }
        if (vm.getPublicKeyJwk() == null) {
            throw new Exception("verification method '" + vm.getId() + "' has no publicKeyJwk");
        }
        String[] parts = proof.getJws() == null ? null : JwsDetached.splitDetachedJws(proof.getJws());
        if (parts == null) {
            throw new Exception("malformed detached JWS");
        }
        // Also enforces b64:false and crit:[b64].
        String alg = JwsDetached.algFromEncodedHeader(parts[0]);

        byte[] signingInput = JwsDetached.signingInput(parts[0], canonicalize());
        byte[] sig;
        try {
            sig = Base64.getUrlDecoder().decode(parts[1]);
        } catch (IllegalArgumentException e) {
            throw new Exception("decode jws signature: " + e.getMessage(), e);
        }
        if (alg == null) {
            alg = "";
        }
        switch (alg) {
            case "ES256" -> {
                PublicKey pub = VerificationMethodMaterial.p256PubKeyFromJwk(vm.getPublicKeyJwk());
                if (sig.length != 64 || !Crypto.verifyEcdsaRaw(pub, sha256(signingInput), sig)) {
                    throw new Exception("JsonWebSignature2020 ES256 signature verification failed");
                }
            }
            case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512" -> Crypto.verifyRsaJws(alg,
                    VerificationMethodMaterial.rsaPubKeyFromJwk(vm.getPublicKeyJwk()), signingInput, sig);
            default -> throw new Exception("unsupported JsonWebSignature2020 alg: \"" + alg + "\"");
        }
        StrictPurposeCheck.enforce(doc, vm, proof.getProofPurpose(), proof.getCreated());
        return true;
    }

    private boolean verifyEcdsaSdProof(CredentialResolver resolver, Proof proof) throws Exception {
        VerificationMethodEntry vmEntry = resolver.findVerificationMethod(proof.getVerificationMethod());
        String didPart = didFromVerificationMethod(proof.getVerificationMethod());
        DIDDocument doc = resolver.resolveDocument(didPart);
        PublicKey publicKey = resolver.ecPublicKeyFromEntry(vmEntry);
        Map<String, Object> docNoProof = bodyWithoutProof();
        EcdsaSd.verifyProof(docNoProof, ecdsaSdProofConfig(proof), proof.getProofValue(), publicKey);
        StrictPurposeCheck.enforce(doc, vmEntry, proof.getProofPurpose(), proof.getCreated());
        return true;
    }

    /**
     * Adds an ecdsa-sd-2023 base proof (DataIntegrityProof).
     */
    public void addECDSASDBaseProof(SignerProvider signerProvider, String verificationMethod, String proofPurpose,
            List<String> mandatoryPointers) throws Exception {
        addECDSASDBaseProof(signerProvider, verificationMethod, proofPurpose, mandatoryPointers, null);
    }

    public void addECDSASDBaseProof(SignerProvider signerProvider, String verificationMethod, String proofPurpose,
            List<String> mandatoryPointers, PublicKey vmPublicKey) throws Exception {
        if (signerProvider == null) {
            throw new IllegalArgumentException("signerProvider cannot be null");
        }
        if (this.get("proof") != null) {
            throw new Exception(
                    "jsonmap: the document already carries a proof; remove the existing proof before adding ecdsa-sd-2023 base proof");
        }
        Object contextBackup = snapshotContext();
        try {
            ensureDataIntegrityContext();
            Proof proof = new Proof();
            proof.setType(DATA_INTEGRITY_PROOF);
            proof.setCryptosuite(ECDSA_SD_2023);
            proof.setCreated(com.pila.credential.common.util.Rfc3339.now());
            proof.setVerificationMethod(verificationMethod);
            proof.setProofPurpose(proofPurpose);
            Map<String, Object> docNoProof = bodyWithoutProof();
            proof.setProofValue(EcdsaSd.createBaseProof(docNoProof, ecdsaSdProofConfig(proof), mandatoryPointers,
                    signerProvider, vmPublicKey));
            appendProof(proof);
        } catch (Exception e) {
            restoreContext(contextBackup);
            throw e;
        }
    }

    public JSONMap deriveECDSASD(List<String> selectivePointers) throws Exception {
        Object proofObj = this.get("proof");
        if (proofObj == null) {
            throw new Exception("jsonmap: credential has no ecdsa-sd-2023 proof to derive from");
        }
        Proof baseProof = parseRawToProof(proofObj instanceof List<?> list && !list.isEmpty() ? list.get(0) : proofObj);
        if (!DATA_INTEGRITY_PROOF.equals(baseProof.getType()) || !ECDSA_SD_2023.equals(baseProof.getCryptosuite())
                || baseProof.getProofValue() == null) {
            throw new Exception("jsonmap: credential has no ecdsa-sd-2023 proof to derive from");
        }
        Map<String, Object> docNoProof = bodyWithoutProof();
        EcdsaSd.DeriveResult derived = EcdsaSd.deriveProofPair(docNoProof, baseProof.getProofValue(),
                selectivePointers);
        JSONMap out = new JSONMap(derived.revealDoc());
        // The derived proof is the base proof with a new proofValue: every other property stays, as
        // the proof configuration it was signed over covers all of them.
        Map<String, Object> derivedProof = new LinkedHashMap<>(baseProof.getRaw());
        derivedProof.put("proofValue", derived.proofValue());
        out.put("proof", derivedProof);
        return out;
    }

    Map<String, Object> ecdsaSdProofConfig(Proof proof) throws Exception {
        return ecdsaProofConfig(proof);
    }

    /** Go's didFromVMURL: the DID of a "did:..." URL, up to an optional '#'. */
    private static String didFromVerificationMethod(String verificationMethodURL) throws Exception {
        if (verificationMethodURL == null || !verificationMethodURL.startsWith("did:")) {
            throw new Exception("proof verificationMethod \"" + verificationMethodURL
                    + "\" is not a DID URL; it must name a key in the signer's DID document");
        }
        int hashIndex = verificationMethodURL.indexOf('#');
        return hashIndex > 0 ? verificationMethodURL.substring(0, hashIndex) : verificationMethodURL;
    }

    /**
     * Verifies an ECDSA-signed JSONMap using DataIntegrityProof.
     */
    private boolean verifyECDSA(PublicKey publicKey, Proof proof) throws Exception {
        if (proof.getProofValue() != null && proof.getProofValue().startsWith("z")) {
            // Only the P-256 profile of ecdsa-rdfc-2019 exists; a secp256k1 or P-384 key is refused up front.
            if (!isP256(publicKey)) {
                throw new Exception("ecdsa-rdfc-2019: verification method \"" + proof.getVerificationMethod()
                        + "\" does not use a P-256 key, but this SDK supports P-256 only");
            }
            byte[] signature = Multibase.decodeBase58Btc(proof.getProofValue());
            if (signature.length != 64) {
                throw new Exception("ecdsa-rdfc-2019 proofValue decodes to " + signature.length
                        + " bytes, want 64 (r||s)");
            }
            byte[] hashData = ecdsaHashData(proof);
            byte[] digest = sha256(hashData);
            return Crypto.verifyEcdsaRaw(publicKey, digest, signature);
        }
        // Legacy hex proofValue (document body only), any curve.
        byte[] doc = legacyDocumentDigest();
        return proof.getProofValue() != null && Crypto.verifyEcdsaHex(publicKey, proof.getProofValue(), doc);
    }

    private static boolean isP256(PublicKey key) {
        if (key instanceof java.security.interfaces.ECPublicKey ec) {
            return ec.getParams().getOrder().equals(
                    CustomNamedCurves.getByName("secp256r1").getN());
        }
        return false;
    }

    private boolean verifyEcdsaSecp256k1Proof(CredentialResolver resolver, Proof proof) throws Exception {
        if (proof.getJws() == null || proof.getJws().isEmpty()) {
            throw new Exception(ECDSA_SECP256K1_SIGNATURE_2019 + ": malformed detached JWS");
        }
        String[] parts = JwsDetached.splitDetachedJws(proof.getJws());
        if (parts == null) {
            throw new Exception(ECDSA_SECP256K1_SIGNATURE_2019 + ": malformed detached JWS");
        }
        String alg = JwsDetached.algFromEncodedHeader(parts[0]);
        if (!ALG_ES256K.equals(alg)) {
            throw new Exception(ECDSA_SECP256K1_SIGNATURE_2019 + ": jws alg must be " + ALG_ES256K + ", got " + alg);
        }
        VerificationMethodEntry vmEntry = resolver.findVerificationMethod(proof.getVerificationMethod());
        if (VerificationMethodKeyKind.fromEntry(vmEntry) != VerificationMethodKeyKind.SECP256K1) {
            throw new Exception(ECDSA_SECP256K1_SIGNATURE_2019 + ": verification method does not hold a secp256k1 key");
        }
        String didPart = didFromVerificationMethod(proof.getVerificationMethod());
        DIDDocument doc = resolver.resolveDocument(didPart);
        PublicKey publicKey = resolver.ecPublicKeyFromEntry(vmEntry);
        byte[] hashData = ecdsaHashData(proof);
        byte[] signingInput = JwsDetached.signingInput(parts[0], hashData);
        byte[] digest = sha256(signingInput);
        byte[] signature = JwsDetached.decodeCanonicalSignature(parts[1]);
        if (signature.length != 64) {
            throw new Exception(ECDSA_SECP256K1_SIGNATURE_2019 + ": jws signature is " + signature.length
                    + " bytes, want 64 (r||s)");
        }
        X9ECParameters ecParams = CustomNamedCurves.getByName("secp256k1");
        BigInteger halfN = ecParams.getN().shiftRight(1);
        BigInteger s = new BigInteger(1, signature, 32, 32);
        if (s.compareTo(halfN) > 0) {
            throw new Exception(ECDSA_SECP256K1_SIGNATURE_2019 + ": jws signature is not low-S");
        }
        if (!Crypto.verifyEcdsaRaw(publicKey, digest, signature)) {
            return false;
        }
        StrictPurposeCheck.enforce(doc, vmEntry, proof.getProofPurpose(), proof.getCreated());
        return true;
    }

    private void appendProof(Proof proof) throws Exception {
        List<Object> merged = new ArrayList<>(rawProofList());
        merged.add(proofToMap(proof));
        this.put("proof", merged.size() == 1 ? merged.get(0) : merged);
    }

    /** The proof as it is written to the document: every parsed property when known, else the typed fields. */
    private static Map<String, Object> proofToMap(Proof proof) {
        if (proof.getRaw() != null) {
            return new LinkedHashMap<>(proof.getRaw());
        }
        Map<String, Object> m = new LinkedHashMap<>();
        putIfNotEmpty(m, "type", proof.getType());
        putIfNotEmpty(m, "created", proof.getCreated());
        putIfNotEmpty(m, "verificationMethod", proof.getVerificationMethod());
        putIfNotEmpty(m, "proofPurpose", proof.getProofPurpose());
        putIfNotEmpty(m, "proofValue", proof.getProofValue());
        putIfNotEmpty(m, "jws", proof.getJws());
        putIfNotEmpty(m, "cryptosuite", proof.getCryptosuite());
        putIfNotEmpty(m, "challenge", proof.getChallenge());
        putIfNotEmpty(m, "domain", proof.getDomain());
        return m;
    }

    private static void putIfNotEmpty(Map<String, Object> m, String k, String v) {
        if (v != null && !v.isEmpty()) {
            m.put(k, v);
        }
    }

    @SuppressWarnings("unchecked")
    private List<Object> rawProofList() {
        Object proofObj = this.get("proof");
        if (proofObj == null) {
            return new ArrayList<>();
        }
        if (proofObj instanceof List) {
            return (List<Object>) proofObj;
        }
        List<Object> single = new ArrayList<>();
        single.add(proofObj);
        return single;
    }

    byte[] documentDigest() throws Exception {
        Map<String, Object> body = bodyWithoutProof();
        // New proofs (ecdsa-rdfc-2019, EcdsaSecp256k1Signature2019 JWS) canonicalize
        // with the library canonicalizer (native JSON types, SafeMode), matching
        // go-credential-sdk. The legacy "compatible" canonicalizer (numbers ->
        // xsd:string) is used only to verify pre-existing hex proofs; see
        // legacyDocumentDigest()/canonicalize(). Signing a numeric claim with the
        // compatible canonicalizer would not interoperate with Go.
        byte[] canonical = Processor.canonicalizeDocumentNativeTypes(body);
        return Processor.computeDigest(canonical);
    }

    private byte[] legacyDocumentDigest() throws Exception {
        return canonicalize();
    }

    byte[] ecdsaHashData(Proof proof) throws Exception {
        byte[] docHash = documentDigest();
        return proofHashData(docHash, proof);
    }

    private byte[] proofHashData(byte[] docHash, Proof proof) throws Exception {
        if (docHash.length != 32) {
            throw new IllegalArgumentException("document digest must be 32 bytes");
        }
        Map<String, Object> cfg = ecdsaProofConfig(proof);
        // Proof config shares the document's canonicalizer: library for new proofs.
        byte[] cfgCanonical = Processor.canonicalizeDocumentNativeTypes(cfg);
        byte[] cfgHash = Processor.computeDigest(cfgCanonical);
        byte[] hashData = new byte[64];
        System.arraycopy(cfgHash, 0, hashData, 0, 32);
        System.arraycopy(docHash, 0, hashData, 32, 32);
        return hashData;
    }

    /**
     * Proof configuration (Data Integrity 3.2.5): the whole proof minus the one field that holds
     * its signature, plus the document's {@code @context}. Nothing else is filtered, so options the
     * signer set (id, expires, nonce, previousProof, array domain, ...) are all hashed.
     */
    Map<String, Object> ecdsaProofConfig(Proof proof) throws Exception {
        if (proof == null) {
            throw new IllegalArgumentException("proof is null");
        }
        Object ctx = this.get("@context");
        if (ctx == null) {
            throw new Exception("document is missing the @context needed to canonicalize the proof configuration");
        }
        Map<String, Object> cfg = new LinkedHashMap<>();
        if (proof.getRaw() != null) {
            cfg.putAll(proof.getRaw());
        } else {
            putIfSet(cfg, "type", proof.getType());
            putIfSet(cfg, "created", proof.getCreated());
            putIfSet(cfg, "verificationMethod", proof.getVerificationMethod());
            putIfSet(cfg, "proofPurpose", proof.getProofPurpose());
            putIfSet(cfg, "cryptosuite", proof.getCryptosuite());
            putIfSet(cfg, "challenge", proof.getChallenge());
            putIfSet(cfg, "domain", proof.getDomain());
            putIfSet(cfg, "proofValue", proof.getProofValue());
            putIfSet(cfg, "jws", proof.getJws());
        }
        cfg.remove(ECDSA_SECP256K1_SIGNATURE_2019.equals(proof.getType()) ? "jws" : "proofValue");
        cfg.put("@context", ctx);
        // JSON round trip: plain JSON types, and a copy so the document's own @context is untouched.
        return objectMapper.readValue(objectMapper.writeValueAsBytes(cfg), new TypeReference<Map<String, Object>>() {
        });
    }

    private static void putIfSet(Map<String, Object> m, String k, String v) {
        if (v != null && !v.isEmpty()) {
            m.put(k, v);
        }
    }

    private Map<String, Object> bodyWithoutProof() {
        Map<String, Object> body = new HashMap<>();
        for (Map.Entry<String, Object> entry : this.entrySet()) {
            if (!"proof".equals(entry.getKey())) {
                body.put(entry.getKey(), entry.getValue());
            }
        }
        return body;
    }

    private void ensureDataIntegrityContext() {
        Object ctx = this.get("@context");
        if (ctx == null) {
            this.put("@context", List.of(DATA_INTEGRITY_V2_CONTEXT));
            return;
        }
        if (ctx instanceof String s) {
            if (!coversDataIntegrity(s)) {
                this.put("@context", List.of(s, DATA_INTEGRITY_V2_CONTEXT));
            }
            return;
        }
        if (ctx instanceof List<?> list) {
            for (Object e : list) {
                if (e instanceof String s && coversDataIntegrity(s)) {
                    return;
                }
            }
            List<Object> next = new ArrayList<>(list);
            next.add(DATA_INTEGRITY_V2_CONTEXT);
            this.put("@context", next);
            return;
        }
        if (ctx instanceof Map<?, ?>) {
            // A bare inline context object defines no proof terms.
            this.put("@context", new ArrayList<>(List.of(ctx, DATA_INTEGRITY_V2_CONTEXT)));
        }
    }

    /**
     * Makes {@code @context} define EcdsaSecp256k1Signature2019 (Go's
     * {@code addSuiteContextWithoutChangingMeaning}) and refuses when adding the suite context changed
     * what the document says: it defines {@code proof} at the root, so a term of that name used
     * elsewhere is redefined and the issuer would sign something other than what it built.
     */
    private void ensureSecp256k1SuiteContext() throws Exception {
        if (definesSecp256k1Suite()) {
            return;
        }
        byte[] before = documentDigest();
        Object ctx = this.get("@context");
        if (ctx instanceof String s) {
            this.put("@context", new ArrayList<>(List.of(s, SECP256K1_SUITE_CONTEXT)));
        } else if (ctx instanceof List<?> list) {
            List<Object> next = new ArrayList<>(list);
            next.add(SECP256K1_SUITE_CONTEXT);
            this.put("@context", next);
        } else if (ctx == null) {
            throw new Exception("document has no @context, so " + ECDSA_SECP256K1_SIGNATURE_2019
                    + " cannot be expanded; add " + SECP256K1_SUITE_CONTEXT + " yourself");
        } else {
            throw new Exception("document @context has unexpected type " + ctx.getClass().getName());
        }
        byte[] after;
        try {
            after = documentDigest();
        } catch (Exception e) {
            throw new Exception("adding " + SECP256K1_SUITE_CONTEXT + ", which " + ECDSA_SECP256K1_SIGNATURE_2019
                    + " needs, stopped the document from canonicalizing; a term it defines collides with one this"
                    + " document uses: " + e.getMessage(), e);
        }
        if (!Arrays.equals(before, after)) {
            throw new Exception("adding " + SECP256K1_SUITE_CONTEXT + ", which " + ECDSA_SECP256K1_SIGNATURE_2019
                    + " needs, changed what the document says; it defines proof at the root, so a term of that"
                    + " name used elsewhere in this document is redefined");
        }
    }

    private boolean definesSecp256k1Suite() {
        Object ctx = this.get("@context");
        if (ctx instanceof String s) {
            return coversSecp256k1Suite(s);
        }
        if (ctx instanceof List<?> list) {
            for (Object e : list) {
                if (e instanceof String s && coversSecp256k1Suite(s)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean coversDataIntegrity(String s) {
        return DATA_INTEGRITY_V2_CONTEXT.equals(s) || "https://www.w3.org/ns/credentials/v2".equals(s);
    }

    private static boolean coversSecp256k1Suite(String s) {
        return SECP256K1_SUITE_CONTEXT.equals(s) || "https://w3id.org/security/v2".equals(s)
                || "https://www.w3.org/2018/credentials/v1".equals(s)
                || "https://www.w3.org/2018/credentials/v1.jsonld".equals(s);
    }

    private static void requireVmAndPurpose(String verificationMethod, String proofPurpose) {
        if (verificationMethod == null || verificationMethod.isEmpty()) {
            throw new IllegalArgumentException("jsonmap: verification method is required");
        }
        if (proofPurpose == null || proofPurpose.isEmpty()) {
            throw new IllegalArgumentException("jsonmap: proof purpose is required");
        }
    }

    /** The secp256k1 suite signs with the VM key; refuse a key on another curve before any signing happens. */
    private static void requireSecp256k1Key(PublicKey vmPublicKey) throws Exception {
        if (vmPublicKey == null) {
            return;
        }
        BigInteger want = CustomNamedCurves.getByName("secp256k1").getN();
        if (!(vmPublicKey instanceof ECPublicKey ec) || !want.equals(ec.getParameters().getN())) {
            throw new Exception(ECDSA_SECP256K1_SIGNATURE_2019 + " requires a secp256k1 verification method key");
        }
    }

    /** Folds a signature into the lower half of the curve order (verifiers reject high-S). */
    private static byte[] normalizeLowS(byte[] sig64) {
        BigInteger n = CustomNamedCurves.getByName("secp256k1").getN();
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(sig64, 32, 64));
        if (s.compareTo(n.shiftRight(1)) <= 0) {
            return sig64;
        }
        byte[] folded = n.subtract(s).toByteArray();
        byte[] out = sig64.clone();
        Arrays.fill(out, 32, 64, (byte) 0);
        int len = Math.min(folded.length, 32);
        System.arraycopy(folded, folded.length - len, out, 64 - len, len);
        return out;
    }

    private Object snapshotContext() {
        return this.get("@context");
    }

    private void restoreContext(Object ctx) {
        if (ctx == null) {
            this.remove("@context");
        } else {
            this.put("@context", ctx);
        }
    }

    private static byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    private static String publicKeyToHex(PublicKey publicKey) throws Exception {
        if (publicKey instanceof org.bouncycastle.jce.interfaces.ECPublicKey ec) {
            byte[] encoded = ec.getQ().getEncoded(false);
            return bytesToHex(encoded);
        }
        throw new Exception("unsupported public key type");
    }

    // Helper methods
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static byte[] hexToBytes(String hex) throws Exception {
        if (hex == null || hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Invalid hex string");
        }

        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            bytes[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return bytes;
    }
}
