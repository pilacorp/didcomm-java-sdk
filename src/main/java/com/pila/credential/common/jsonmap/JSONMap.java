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
     * Adds an ECDSA proof to the JSONMap.
     */
    @Deprecated
    public void addECDSAProof(String privKeyHex,
            String verificationMethod,
            String proofPurpose) throws Exception {
        addECDSAProofByProvider(new DefaultSignerProvider(privKeyHex), verificationMethod, proofPurpose);
    }

    /**
     * Legacy overload kept for backward compatibility.
     *
     * @deprecated Use {@link #addECDSAProofByProvider(SignerProvider, String, String, String)}.
     */
    @Deprecated
    public void addECDSAProof(String privKeyHex,
            String verificationMethod,
            String proofPurpose,
            String didBaseURL) throws Exception {
        addECDSAProofByProvider(new DefaultSignerProvider(privKeyHex), verificationMethod, proofPurpose, didBaseURL);
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
        Object contextBackup = snapshotContext();
        try {
            ensureDataIntegrityContext();

            Proof proof = new Proof();
            proof.setType(DATA_INTEGRITY_PROOF);
            proof.setCreated(Instant.now().toString());
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
        Object contextBackup = snapshotContext();
        try {
            ensureSecp256k1SuiteContext();

            Proof proof = new Proof();
            proof.setType(ECDSA_SECP256K1_SIGNATURE_2019);
            proof.setCreated(Instant.now().toString());
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
     * Builds section 3.2.4 hashData from a document digest and proof options.
     */
    public byte[] createProofSigning(byte[] docHash, Proof proof) throws Exception {
        return proofHashData(docHash, proof);
    }

    /**
     * Adds a custom proof to the JSONMap.
     */
    public void addCustomProof(Proof proof) throws Exception {
        if (proof == null) {
            throw new IllegalArgumentException("proof is null");
        }
        appendProof(proof);
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
        return verifyProof(new ChainingCredentialResolver(
                new DidKeyP256Resolver(),
                new VerificationMethodResolver(didBaseURL)));
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
            Object issuerObj = this.get("issuer");
            if (!(issuerObj instanceof String)) {
                throw new Exception("issuer is missing or invalid in the request");
            }
            String publicKey = resolver.getDefaultPublicKeyHex((String) issuerObj);
            Map<String, Object> reqMap = new HashMap<>(this);
            if (!Crypto.verifyJwtProof(reqMap, publicKey)) {
                return false;
            }
            if (proof.getVerificationMethod() != null && !proof.getVerificationMethod().isEmpty()) {
                String didPart = didFromVerificationMethod(proof.getVerificationMethod());
                DIDDocument doc = resolver.resolveDocument(didPart);
                VerificationMethodEntry vm = resolver.findVerificationMethod(proof.getVerificationMethod());
                StrictPurposeCheck.enforce(doc, vm, "assertionMethod", proof.getCreated());
            }
            return true;
        }
        if (ECDSA_SECP256K1_SIGNATURE_2019.equals(proof.getType())
                || ECDSA_SECP_KEY.equals(proof.getType())) {
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
            proof.setCreated(Instant.now().toString());
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
        Proof derivedProof = new Proof();
        derivedProof.setType(baseProof.getType());
        derivedProof.setCryptosuite(baseProof.getCryptosuite());
        derivedProof.setCreated(baseProof.getCreated());
        derivedProof.setVerificationMethod(baseProof.getVerificationMethod());
        derivedProof.setProofPurpose(baseProof.getProofPurpose());
        derivedProof.setProofValue(derived.proofValue());
        out.addCustomProof(derivedProof);
        return out;
    }

    Map<String, Object> ecdsaSdProofConfig(Proof proof) throws Exception {
        Object ctx = this.get("@context");
        if (ctx == null) {
            throw new Exception("document is missing the @context needed to canonicalize the proof configuration");
        }
        Map<String, Object> cfg = new LinkedHashMap<>();
        cfg.put("type", proof.getType());
        cfg.put("created", proof.getCreated());
        cfg.put("verificationMethod", proof.getVerificationMethod());
        cfg.put("proofPurpose", proof.getProofPurpose());
        cfg.put("@context", ctx);
        if (proof.getCryptosuite() != null) {
            cfg.put("cryptosuite", proof.getCryptosuite());
        }
        return cfg;
    }

    private static String didFromVerificationMethod(String verificationMethodURL) throws Exception {
        int hashIndex = verificationMethodURL.indexOf('#');
        if (hashIndex <= 0) {
            throw new Exception("verification method " + verificationMethodURL + " is not a DID URL");
        }
        return verificationMethodURL.substring(0, hashIndex);
    }

    /**
     * Verifies an ECDSA-signed JSONMap using DataIntegrityProof.
     */
    private boolean verifyECDSA(PublicKey publicKey, Proof proof) throws Exception {
        if (proof.getProofValue() != null && proof.getProofValue().startsWith("z")) {
            byte[] signature = Multibase.decodeBase58Btc(proof.getProofValue());
            if (signature.length != 64) {
                return false;
            }
            byte[] hashData = ecdsaHashData(proof);
            byte[] digest = sha256(hashData);
            return Crypto.verifyEcdsaRaw(publicKey, digest, signature);
        }
        // Legacy hex proofValue (document body only).
        byte[] doc = legacyDocumentDigest();
        return Crypto.ecdsaVerifySignature(publicKeyToHex(publicKey), proof.getProofValue(), doc);
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
        if (signature.length == 65) {
            signature = Arrays.copyOf(signature, 64);
        }
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
        List<Proof> merged = new ArrayList<>();
        for (Object raw : rawProofList()) {
            merged.add(parseRawToProof(raw));
        }
        merged.add(proof);
        this.put("proof", VCUtil.serializeProofs(merged));
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
        byte[] canonical = Processor.canonicalizeDocument(body);
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
        byte[] cfgCanonical = Processor.canonicalizeDocument(cfg);
        byte[] cfgHash = Processor.computeDigest(cfgCanonical);
        byte[] hashData = new byte[64];
        System.arraycopy(cfgHash, 0, hashData, 0, 32);
        System.arraycopy(docHash, 0, hashData, 32, 32);
        return hashData;
    }

    @SuppressWarnings("unchecked")
    Map<String, Object> ecdsaProofConfig(Proof proof) throws Exception {
        Map<String, Object> cfg = objectMapper.convertValue(proof, Map.class);
        String sigField = ECDSA_SECP256K1_SIGNATURE_2019.equals(proof.getType()) ? "jws" : "proofValue";
        cfg.remove(sigField);
        cfg.put("@context", this.get("@context"));
        byte[] normalized = objectMapper.writeValueAsBytes(cfg);
        return objectMapper.readValue(normalized, new TypeReference<Map<String, Object>>() {
        });
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
        }
    }

    private void ensureSecp256k1SuiteContext() {
        Object ctx = this.get("@context");
        if (ctx instanceof String s) {
            if (!coversSecp256k1Suite(s)) {
                this.put("@context", List.of(s, SECP256K1_SUITE_CONTEXT));
            }
            return;
        }
        if (ctx instanceof List<?> list) {
            for (Object e : list) {
                if (e instanceof String s && coversSecp256k1Suite(s)) {
                    return;
                }
            }
            List<Object> next = new ArrayList<>(list);
            next.add(SECP256K1_SUITE_CONTEXT);
            this.put("@context", next);
        }
    }

    private static boolean coversDataIntegrity(String s) {
        return DATA_INTEGRITY_V2_CONTEXT.equals(s) || "https://www.w3.org/ns/credentials/v2".equals(s);
    }

    private static boolean coversSecp256k1Suite(String s) {
        return SECP256K1_SUITE_CONTEXT.equals(s) || "https://w3id.org/security/v2".equals(s)
                || "https://www.w3.org/2018/credentials/v1".equals(s);
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
