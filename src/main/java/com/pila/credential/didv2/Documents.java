package com.pila.credential.didv2;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.pila.credential.common.verificationmethod.DIDDocument;
import com.pila.credential.common.verificationmethod.Multikey;
import com.pila.credential.common.verificationmethod.VerificationMethodEntry;
import com.pila.credential.didv2.did.DIDDocumentOps;
import com.pila.credential.did.VerificationPurpose;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public final class Documents {
    private static final ObjectMapper MAPPER = new ObjectMapper().configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, false);

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private Documents() {
    }

    /** A secp256k1 key pair; the scalar is uniform over [1, n-1] (Go crypto.GenerateKey). */
    public static KeyPair generateECDSAKeyPair() {
        SecureRandom rnd = new SecureRandom();
        BigInteger d;
        do {
            byte[] raw = new byte[32];
            rnd.nextBytes(raw);
            d = new BigInteger(1, raw);
        } while (d.signum() == 0 || d.compareTo(Secp256k1.N) >= 0);
        byte[] priv = Hex.toFixed(d.toByteArray(), 32);
        byte[] pub = Secp256k1.publicFromPrivate(priv, true);
        KeyPair kp = new KeyPair();
        kp.privateKeyHex = Hex.encode0x(priv);
        kp.publicKeyHex = Hex.encode0x(pub);
        kp.address = Secp256k1.addressFromPublicKey(pub);
        return kp;
    }

    public static KeyPair generateDualCurveDIDKeyPair() throws Exception {
        var spec = ECNamedCurveTable.getParameterSpec("prime256v1");
        var kpg = java.security.KeyPairGenerator.getInstance("EC", "BC");
        kpg.initialize(spec, new SecureRandom());
        var javaKp = kpg.generateKeyPair();
        BigInteger d = ((org.bouncycastle.jce.interfaces.ECPrivateKey) javaKp.getPrivate()).getD();
        byte[] scalar = Hex.toFixed(d.toByteArray(), 32);
        byte[] compressed = Secp256k1.publicFromPrivate(scalar, true);
        var p256Pub = (org.bouncycastle.jce.interfaces.ECPublicKey) javaKp.getPublic();
        byte[] uncompressed = p256Pub.getQ().getEncoded(false);
        KeyPair kp = new KeyPair();
        kp.privateKeyHex = Hex.encode0x(scalar);
        kp.publicKeyHex = Hex.encode0x(compressed);
        kp.address = Secp256k1.addressFromPublicKey(compressed);
        kp.p256X = Hex.encode(java.util.Arrays.copyOfRange(uncompressed, 1, 33));
        kp.p256Y = Hex.encode(java.util.Arrays.copyOfRange(uncompressed, 33, 65));
        return kp;
    }

    public static VerificationMethodEntry newSecp256k1VM(String did, String fragment, String publicKeyHex) {
        VerificationMethodEntry vm = new VerificationMethodEntry();
        vm.setId(DIDDocumentOps.canonicalVmId(did, fragment));
        vm.setType(DIDDocumentOps.SECP256K1_VM_TYPE);
        vm.setController(did);
        vm.setPublicKeyHex(publicKeyHex);
        return vm;
    }

    public static VerificationMethodEntry newP256MultikeyVM(String did, String fragment, String xHex, String yHex)
            throws Exception {
        byte[] xy = Hex.decode(xHex + yHex);
        VerificationMethodEntry vm = new VerificationMethodEntry();
        vm.setId(DIDDocumentOps.canonicalVmId(did, fragment));
        vm.setType(DIDDocumentOps.MULTIKEY_VM_TYPE);
        vm.setController(did);
        vm.setPublicKeyMultibase(Multikey.encodeP256PublicXY(xy));
        return vm;
    }

    /** Go NewP256MultikeyVM(did, frag, *ecdsa.PublicKey): a Multikey VM from a P-256 public key. */
    public static VerificationMethodEntry newP256MultikeyVM(String did, String fragment,
            java.security.interfaces.ECPublicKey pub) throws Exception {
        if (pub == null) {
            throw new Exception("NewP256MultikeyVM requires a P-256 public key");
        }
        VerificationMethodEntry vm = new VerificationMethodEntry();
        vm.setId(DIDDocumentOps.canonicalVmId(did, fragment));
        vm.setType(DIDDocumentOps.MULTIKEY_VM_TYPE);
        vm.setController(did);
        vm.setPublicKeyMultibase(Multikey.encodeP256PublicKey(pub));
        return vm;
    }

    /** Go NewSpec: pairs a VM with its purposes; no purpose means both. */
    public static VmSpec newSpec(VerificationMethodEntry vm, VerificationPurpose... purposes) {
        return new VmSpec(vm, purposes == null || purposes.length == 0 ? null : List.of(purposes));
    }

    /**
     * Go GenerateDIDDocument: null (not an exception) when the verification-method specs cannot be built, e.g. an
     * unsupported purpose; a caller then fails in {@link #validateDIDDocument}("DID document is nil").
     */
    public static DIDDocument generateDIDDocument(String didPublicKey, String did, String hash, String issuerDID,
            int didType, Map<String, Object> metadata, List<VmSpec> extraVMs) throws Exception {
        Map<String, Object> docMetadata = new TreeMap<>();
        if (metadata != null) {
            docMetadata.putAll(sortObject(metadata));
        }
        String typeName = Types.didTypeString(didType);
        if (typeName != null && !typeName.isEmpty()) {
            docMetadata.put("type", typeName);
        }
        if (hash != null && !hash.isEmpty()) {
            docMetadata.put("hash", hash);
        }
        List<VmSpec> specs = new ArrayList<>();
        specs.add(new VmSpec(newSecp256k1VM(did, "#key-1", didPublicKey), null));
        if (extraVMs != null) {
            specs.addAll(extraVMs);
        }
        Built built;
        try {
            built = newVerificationMethods(specs);
        } catch (Exception e) {
            return null;
        }
        DIDDocument doc = new DIDDocument();
        doc.setContext(documentContext(built.vms));
        doc.setId(did);
        doc.setController(issuerDID);
        doc.setVerificationMethod(built.vms);
        doc.setAuthentication(built.authentication);
        doc.setAssertionMethod(built.assertionMethod);
        doc.setDidDocumentMetadata(new TreeMap<>(docMetadata));
        return doc;
    }

    public static void validateDIDDocument(DIDDocument doc) throws Exception {
        if (doc == null) {
            throw new Exception("DID document is nil");
        }
        java.util.Set<String> seen = new java.util.HashSet<>();
        List<VerificationMethodEntry> vms = doc.getVerificationMethod();
        if (vms == null) {
            vms = List.of();
        }
        for (int i = 0; i < vms.size(); i++) {
            VerificationMethodEntry vm = vms.get(i);
            if (vm.getId() == null || vm.getId().isEmpty()) {
                throw new Exception("verificationMethod[" + i + "]: id is empty");
            }
            if (!seen.add(vm.getId())) {
                throw new Exception("verificationMethod: duplicate id " + vm.getId()
                        + " (#key-1 and #key-2 are reserved by GenerateDID)");
            }
            String expected = DIDDocumentOps.vmTypeFor(vm);
            if (!expected.equals(vm.getType())) {
                throw new Exception("verificationMethod[" + i + "] (" + vm.getId() + "): type \"" + vm.getType()
                        + "\" does not match its key material: expected " + expected);
            }
        }
        checkRefs("authentication", doc.getAuthentication(), doc.getId(), seen);
        checkRefs("assertionMethod", doc.getAssertionMethod(), doc.getId(), seen);
    }

    public static String hashDIDDocument(DIDDocument doc) throws Exception {
        if (doc == null) {
            throw new Exception("DID document is nil");
        }
        byte[] marshaled = marshalGoJSON(doc).getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] canonical = Rfc8785.transform(marshaled);
        return Keccak256.hashHex(canonical);
    }

    /**
     * The JSON Go's {@code json.Marshal(*did.DIDDocument)} produces (before JCS): nil slices and maps are
     * {@code null}, strings are never null, {@code publicKeyJwk} is the whole map ({@code omitempty}), and
     * {@code revoked} is a {@code *time.Time}, re-marshalled as RFC3339Nano (a malformed value is an error).
     */
    public static String marshalGoJSON(DIDDocument doc) throws Exception {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("@context", doc.getContext());
        root.put("id", doc.getId() == null ? "" : doc.getId());
        Object controller = doc.getController();
        root.put("controller", controller == null ? "" : controller);
        List<Map<String, Object>> vms = null;
        if (doc.getVerificationMethod() != null) {
            vms = new ArrayList<>();
            for (VerificationMethodEntry vm : doc.getVerificationMethod()) {
                vms.add(vmJSON(vm));
            }
        }
        root.put("verificationMethod", vms);
        root.put("authentication", doc.getAuthentication());
        root.put("assertionMethod", doc.getAssertionMethod());
        root.put("didDocumentMetadata",
                doc.getDidDocumentMetadata() == null ? null : sortObject(doc.getDidDocumentMetadata()));
        return MAPPER.writeValueAsString(root);
    }

    /** Go AddressFromPublicKeyHex: 33-byte compressed or 65-byte uncompressed, on secp256k1; only "0x" is stripped. */
    public static String addressFromPublicKeyHex(String publicKeyHex) throws Exception {
        byte[] bytes;
        try {
            bytes = Hex.decodeGo(publicKeyHex);
        } catch (IllegalArgumentException e) {
            throw new Exception("failed to decode public key hex: " + e.getMessage(), e);
        }
        boolean compressed = bytes.length == 33 && (bytes[0] == 0x02 || bytes[0] == 0x03);
        boolean uncompressed = bytes.length == 65 && bytes[0] == 0x04;
        if (!compressed && !uncompressed) {
            throw new Exception("unsupported public key format: expected 33 bytes (compressed) or 65 bytes (uncompressed), got "
                    + bytes.length + " bytes");
        }
        try {
            return Secp256k1.addressFromPublicKey(bytes);
        } catch (RuntimeException e) {
            throw new Exception((compressed ? "failed to decompress public key: " : "failed to unmarshal public key: ")
                    + e.getMessage(), e);
        }
    }

    public static final class VmSpec {
        public final VerificationMethodEntry vm;
        public final List<VerificationPurpose> purposes;

        public VmSpec(VerificationMethodEntry vm, List<VerificationPurpose> purposes) {
            this.vm = vm;
            this.purposes = purposes;
        }
    }

    /** Go NewVerificationMethods: splits complete specs into the VMs and the two relationship arrays. */
    public static Built newVerificationMethods(List<VmSpec> specs) throws Exception {
        Built b = new Built();
        for (VmSpec s : specs) {
            b.vms.add(s.vm);
            List<VerificationPurpose> purposes = s.purposes == null || s.purposes.isEmpty()
                    ? List.of(VerificationPurpose.AUTHENTICATION, VerificationPurpose.ASSERTION_METHOD)
                    : s.purposes;
            for (VerificationPurpose p : purposes) {
                if (p == VerificationPurpose.AUTHENTICATION) {
                    b.authentication.add(s.vm.getId());
                } else if (p == VerificationPurpose.ASSERTION_METHOD) {
                    b.assertionMethod.add(s.vm.getId());
                } else {
                    throw new Exception("verification method " + s.vm.getId() + ": unsupported purpose: " + p);
                }
            }
        }
        return b;
    }

    private static List<String> documentContext(List<VerificationMethodEntry> vms) {
        List<String> ctx = new ArrayList<>(List.of("https://www.w3.org/ns/did/v1", "https://w3id.org/security/v1"));
        for (VerificationMethodEntry vm : vms) {
            if (DIDDocumentOps.MULTIKEY_VM_TYPE.equals(vm.getType())) {
                ctx.add(DIDDocumentOps.CID_CONTEXT);
                break;
            }
        }
        return ctx;
    }

    private static Map<String, Object> vmJSON(VerificationMethodEntry vm) throws Exception {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("id", vm.getId() == null ? "" : vm.getId());
        out.put("type", vm.getType() == null ? "" : vm.getType());
        out.put("controller", vm.getController() == null ? "" : vm.getController());
        if (vm.getPublicKeyHex() != null && !vm.getPublicKeyHex().isEmpty()) {
            out.put("publicKeyHex", vm.getPublicKeyHex());
        }
        if (vm.getPublicKeyJwk() != null && !vm.getPublicKeyJwk().isEmpty()) {
            out.put("publicKeyJwk", vm.getPublicKeyJwk().toMap());
        }
        if (vm.getPublicKeyMultibase() != null && !vm.getPublicKeyMultibase().isEmpty()) {
            out.put("publicKeyMultibase", vm.getPublicKeyMultibase());
        }
        if (vm.getRevoked() != null && !vm.getRevoked().isEmpty()) {
            out.put("revoked", Rfc3339Nano.normalize(vm.getRevoked()));
        }
        if (vm.getRevocationReason() != null && !vm.getRevocationReason().isEmpty()) {
            out.put("revocationReason", vm.getRevocationReason());
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> sortObject(Map<String, Object> input) {
        Map<String, Object> out = new TreeMap<>();
        for (Map.Entry<String, Object> e : input.entrySet()) {
            Object v = e.getValue();
            if (v instanceof Map<?, ?> m) {
                out.put(e.getKey(), sortObject((Map<String, Object>) m));
            } else {
                out.put(e.getKey(), v);
            }
        }
        return out;
    }

    private static void checkRefs(String name, List<String> refs, String did, java.util.Set<String> seen)
            throws Exception {
        if (refs == null) {
            return;
        }
        for (String ref : refs) {
            String id = DIDDocumentOps.canonicalVmId(did, ref);
            if (!seen.contains(id)) {
                throw new Exception(name + " references unknown verification method \"" + ref + "\"");
            }
        }
    }

    public static final class Built {
        public final List<VerificationMethodEntry> vms = new ArrayList<>();
        public final List<String> authentication = new ArrayList<>();
        public final List<String> assertionMethod = new ArrayList<>();
    }
}
