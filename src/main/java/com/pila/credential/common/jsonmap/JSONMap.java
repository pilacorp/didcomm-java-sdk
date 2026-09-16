package com.pila.credential.common.jsonmap;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.crypto.Crypto;
import com.pila.credential.common.dto.Proof;
import com.pila.credential.common.processor.Processor;
import com.pila.credential.common.signer.DefaultSignerProvider;
import com.pila.credential.common.signer.SignerProvider;
import com.pila.credential.common.util.VCUtil;
import com.pila.credential.common.verificationmethod.VerificationMethodResolver;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
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
    public static final String ECDSA_SECP_KEY = "EcdsaSecp256k1VerificationKey2019";

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
     *
     * <p>
     * This method computes {@code digest32 = canonicalize()}, which already returns a 32-byte SHA-256
     * digest of the canonical N-Quads form. The provider is expected to sign that digest.
     *
     * <p>
     * The resulting {@code proofValue} is stored as hex of the raw signature bytes and accepts
     * 64 bytes (R||S) or 65 bytes (R||S||V).
     */
    public void addECDSAProofByProvider(SignerProvider signerProvider,
            String verificationMethod,
            String proofPurpose) throws Exception {
        addECDSAProofByProvider(signerProvider, verificationMethod, proofPurpose, null);
    }

    /**
     * Adds a DataIntegrityProof (ecdsa-rdfc-2019) using a signing provider and optionally verifies it
     * against a DID resolver before mutating state.
     *
     * <p>If {@code didBaseURL} is non-empty, the SDK resolves the public key from {@code verificationMethod}
     * and verifies the produced signature over the computed digest32. If verification fails, no proof is attached.</p>
     */
    public void addECDSAProofByProvider(SignerProvider signerProvider,
            String verificationMethod,
            String proofPurpose,
            String didBaseURL) throws Exception {
        if (signerProvider == null) {
            throw new IllegalArgumentException("signerProvider cannot be null");
        }
        if (verificationMethod == null || verificationMethod.isEmpty()) {
            throw new IllegalArgumentException("verification method is required");
        }
        if (proofPurpose == null || proofPurpose.isEmpty()) {
            throw new IllegalArgumentException("proof purpose is required");
        }

        Proof proof = new Proof();
        proof.setType(DATA_INTEGRITY_PROOF);
        proof.setCreated(Instant.now().toString());
        proof.setVerificationMethod(verificationMethod);
        proof.setProofPurpose(proofPurpose);
        proof.setCryptosuite(ECDSA_RDFC_2019);

        byte[] signData = this.canonicalize();
        if (signData == null || signData.length != 32) {
            throw new IllegalArgumentException("digest must be 32 bytes");
        }
        byte[] signature = signerProvider.sign(signData);
        if (signature == null || (signature.length != 64 && signature.length != 65)) {
            throw new IllegalArgumentException("signature length must be 64 or 65");
        }
        proof.setProofValue(bytesToHex(signature));

        if (didBaseURL != null && !didBaseURL.isBlank()) {
            VerificationMethodResolver resolver = new VerificationMethodResolver(didBaseURL);
            String publicKeyHex = resolver.getPublicKey(verificationMethod);
            boolean ok = Crypto.ecdsaVerifySignature(publicKeyHex, proof.getProofValue(), signData);
            if (!ok) {
                throw new Exception("signature verification failed");
            }
        }

        List<Proof> proofs = new ArrayList<>();
        proofs.add(proof);
        this.put("proof", VCUtil.serializeProofs(proofs));
    }


    /**
     * Adds a custom proof to the JSONMap.
     */
    public void addCustomProof(Proof proof) throws Exception {
        if (proof == null) {
            throw new IllegalArgumentException("proof is null");
        }

        List<Proof> proofs = new ArrayList<>();
        proofs.add(proof);
        this.put("proof", VCUtil.serializeProofs(proofs));
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

        return result;
    }

    /**
     * Verifies an ECDSA-signed JSONMap.
     */
    public boolean verifyProof(String didBaseURL) throws Exception {
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

        Proof proof = parseRawToProof(proofs.get(0));

        if (JWT_PROOF_2020.equals(proof.getType())) {
            Object issuerObj = this.get("issuer");
            if (!(issuerObj instanceof String)) {
                throw new Exception("issuer is missing or invalid in the request");
            }

            String issuerDID = (String) issuerObj;
            VerificationMethodResolver resolver = new VerificationMethodResolver(didBaseURL);
            String publicKey = resolver.getDefaultPublicKey(issuerDID);

            Map<String, Object> reqMap = new HashMap<>(this);
            return Crypto.verifyJwtProof(reqMap, publicKey);

        } else if (ECDSA_SECP256K1_SIGNATURE_2019.equals(proof.getType())
                || ECDSA_SECP_KEY.equals(proof.getType())) {

            // Two encodings exist in the wild for this proof type: a raw hex proofValue
            // (legacy) and a detachable ES256K JWS, which the wallet SDKs emit.
            if (proof.getJws() != null && !proof.getJws().isEmpty()) {
                return verifyJwsProof(didBaseURL, proof);
            }
            return verifyEcdsaProofLegacy();

        } else if (DATA_INTEGRITY_PROOF.equals(proof.getType())
                && ECDSA_RDFC_2019.equals(proof.getCryptosuite())) {

            VerificationMethodResolver resolver = new VerificationMethodResolver(didBaseURL);
            String publicKey = resolver.getPublicKey(proof.getVerificationMethod());
            return verifyECDSA(publicKey, proof);

        } else {
            throw new Exception("unsupported proof type: " + proof.getType());
        }
    }

    /**
     * Verifies an ECDSA-signed JSONMap using DataIntegrityProof.
     */
    private boolean verifyECDSA(String publicKeyHex, Proof proof) throws Exception {
        byte[] doc = this.canonicalize();
        return Crypto.ecdsaVerifySignature(publicKeyHex, proof.getProofValue(), doc);
    }

    /**
     * Verifies an {@code EcdsaSecp256k1Signature2019} proof carried as an ES256K JWS.
     *
     * <p>
     * The JWS payload is the signed document without its proof. It is compared against this
     * document before the signature is checked, so a signature made over different content cannot
     * be replayed onto this one.
     */
    private boolean verifyJwsProof(String didBaseURL, Proof proof) throws Exception {
        String[] parts = proof.getJws().split("\\.");
        if (parts.length != 3) {
            throw new Exception("proof jws is malformed: expected three parts");
        }
        if (parts[1].isEmpty()) {
            throw new Exception("detached jws payloads are not supported");
        }

        Base64.Decoder decoder = Base64.getUrlDecoder();

        Map<String, Object> header = objectMapper.readValue(decoder.decode(parts[0]),
                new TypeReference<Map<String, Object>>() {
                });
        Object alg = header.get("alg");
        if (!"ES256K".equals(alg)) {
            throw new Exception("unsupported jws algorithm: " + alg);
        }

        // Bind the signed payload to this document: everything except the proof must match.
        Map<String, Object> payload = objectMapper.readValue(decoder.decode(parts[1]),
                new TypeReference<Map<String, Object>>() {
                });
        Map<String, Object> expected = new HashMap<>(this);
        expected.remove("proof");
        if (!payload.equals(expected)) {
            throw new Exception("jws payload does not match the document it is attached to");
        }

        String verificationMethod = proof.getVerificationMethod();
        if (verificationMethod == null || verificationMethod.isEmpty()) {
            Object kid = header.get("kid");
            verificationMethod = kid != null ? kid.toString() : null;
        }
        if (verificationMethod == null || verificationMethod.isEmpty()) {
            throw new Exception("proof verificationMethod is missing or invalid in the request");
        }

        VerificationMethodResolver resolver = new VerificationMethodResolver(didBaseURL);
        String publicKey = resolver.getDefaultPublicKey(verificationMethod);

        byte[] signingInput = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(signingInput);
        byte[] signature = decoder.decode(parts[2]);

        return Crypto.ecdsaVerifySignature(publicKey, bytesToHex(signature), digest);
    }

    /**
     * Verifies an ECDSA-signed JSONMap (legacy format).
     */
    private boolean verifyEcdsaProofLegacy() throws Exception {
        Object proofObj = this.get("proof");
        if (!(proofObj instanceof Map)) {
            throw new Exception("proof value is missing or invalid in the request");
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> proofMap = (Map<String, Object>) proofObj;

        Object proofValueObj = proofMap.get("proofValue");
        if (!(proofValueObj instanceof String) || ((String) proofValueObj).isEmpty()) {
            throw new Exception("proof value is missing or invalid in the request");
        }

        String proofValue = (String) proofValueObj;

        Object verificationMethodObj = proofMap.get("verificationMethod");
        if (!(verificationMethodObj instanceof String) || ((String) verificationMethodObj).isEmpty()) {
            throw new Exception("proof verificationMethod is missing or invalid in the request");
        }

        String publicKeyHex = (String) verificationMethodObj;

        byte[] signatureBytes = hexToBytes(proofValue);

        Map<String, Object> reqCopy = new HashMap<>();
        for (Map.Entry<String, Object> entry : this.entrySet()) {
            if (!"proof".equals(entry.getKey())) {
                reqCopy.put(entry.getKey(), entry.getValue());
            }
        }

        byte[] message = objectMapper.writeValueAsBytes(reqCopy);

        byte[] pubBytes = Crypto.keyToBytes(publicKeyHex);

        return Crypto.verifyJSONSignature(pubBytes, message, signatureBytes);
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
