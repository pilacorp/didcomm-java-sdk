package com.pila.credential.didv2;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.pila.credential.common.verificationmethod.DIDDocument;
import com.pila.credential.common.verificationmethod.Multikey;
import com.pila.credential.common.verificationmethod.VerificationMethodEntry;
import com.pila.credential.did.VerificationMethodOps;
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

    public static KeyPair generateECDSAKeyPair() {
        byte[] priv = new byte[32];
        new SecureRandom().nextBytes(priv);
        priv[0] &= 0x7f;
        if (priv[31] == 0) {
            priv[31] = 1;
        }
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
        vm.setId(VerificationMethodOps.canonicalVmId(did, fragment));
        vm.setType(VerificationMethodOps.SECP256K1_VM_TYPE);
        vm.setController(did);
        vm.setPublicKeyHex(publicKeyHex);
        return vm;
    }

    public static VerificationMethodEntry newP256MultikeyVM(String did, String fragment, String xHex, String yHex)
            throws Exception {
        byte[] xy = Hex.decode(xHex + yHex);
        VerificationMethodEntry vm = new VerificationMethodEntry();
        vm.setId(VerificationMethodOps.canonicalVmId(did, fragment));
        vm.setType(VerificationMethodOps.MULTIKEY_VM_TYPE);
        vm.setController(did);
        vm.setPublicKeyMultibase(Multikey.encodeP256PublicXY(xy));
        return vm;
    }

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
        Built built = newVerificationMethods(specs);
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
            String expected = VerificationMethodOps.vmTypeFor(vm);
            if (!expected.equals(vm.getType())) {
                throw new Exception("verificationMethod[" + i + "] (" + vm.getId() + "): type \"" + vm.getType()
                        + "\" does not match its key material: expected " + expected);
            }
        }
        checkRefs("authentication", doc.getAuthentication(), doc.getId(), seen);
        checkRefs("assertionMethod", doc.getAssertionMethod(), doc.getId(), seen);
    }

    public static String hashDIDDocument(DIDDocument doc) throws Exception {
        byte[] marshaled = marshalGoJSON(doc).getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] canonical = Rfc8785.transform(marshaled);
        return Keccak256.hashHex(canonical);
    }

    public static String marshalGoJSON(DIDDocument doc) throws Exception {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("@context", doc.getContext());
        root.put("id", doc.getId());
        Object controller = doc.getController();
        root.put("controller", controller == null ? "" : controller);
        List<Map<String, Object>> vms = new ArrayList<>();
        if (doc.getVerificationMethod() != null) {
            for (VerificationMethodEntry vm : doc.getVerificationMethod()) {
                vms.add(vmJSON(vm));
            }
        }
        root.put("verificationMethod", vms);
        root.put("authentication", doc.getAuthentication() == null ? List.of() : doc.getAuthentication());
        root.put("assertionMethod", doc.getAssertionMethod() == null ? List.of() : doc.getAssertionMethod());
        root.put("didDocumentMetadata", sortObject(doc.getDidDocumentMetadata() == null ? Map.of() : doc.getDidDocumentMetadata()));
        return MAPPER.writeValueAsString(root);
    }

    public static String addressFromPublicKeyHex(String publicKeyHex) throws Exception {
        byte[] bytes = Hex.decode(publicKeyHex);
        if (bytes.length == 33 && (bytes[0] == 0x02 || bytes[0] == 0x03)) {
            return Secp256k1.addressFromPublicKey(bytes);
        }
        if (bytes.length == 65 && bytes[0] == 0x04) {
            return Secp256k1.addressFromPublicKey(bytes);
        }
        throw new Exception("unsupported public key format: expected 33 bytes (compressed) or 65 bytes (uncompressed), got "
                + bytes.length + " bytes");
    }

    public static final class VmSpec {
        public final VerificationMethodEntry vm;
        public final List<VerificationPurpose> purposes;

        public VmSpec(VerificationMethodEntry vm, List<VerificationPurpose> purposes) {
            this.vm = vm;
            this.purposes = purposes;
        }
    }

    private static Built newVerificationMethods(List<VmSpec> specs) throws Exception {
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
                    throw new Exception("unsupported purpose");
                }
            }
        }
        return b;
    }

    private static List<String> documentContext(List<VerificationMethodEntry> vms) {
        List<String> ctx = new ArrayList<>(List.of("https://www.w3.org/ns/did/v1", "https://w3id.org/security/v1"));
        for (VerificationMethodEntry vm : vms) {
            if (VerificationMethodOps.MULTIKEY_VM_TYPE.equals(vm.getType())) {
                ctx.add(VerificationMethodOps.CID_CONTEXT);
                break;
            }
        }
        return ctx;
    }

    private static Map<String, Object> vmJSON(VerificationMethodEntry vm) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("id", vm.getId());
        out.put("type", vm.getType());
        out.put("controller", vm.getController());
        if (vm.getPublicKeyHex() != null && !vm.getPublicKeyHex().isEmpty()) {
            out.put("publicKeyHex", vm.getPublicKeyHex());
        }
        if (vm.getPublicKeyJwk() != null) {
            out.put("publicKeyJwk", vm.getPublicKeyJwk());
        }
        if (vm.getPublicKeyMultibase() != null && !vm.getPublicKeyMultibase().isEmpty()) {
            out.put("publicKeyMultibase", vm.getPublicKeyMultibase());
        }
        if (vm.getRevoked() != null && !vm.getRevoked().isEmpty()) {
            out.put("revoked", vm.getRevoked());
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
            String id = VerificationMethodOps.canonicalVmId(did, ref);
            if (!seen.contains(id)) {
                throw new Exception(name + " references unknown verification method \"" + ref + "\"");
            }
        }
    }

    private static final class Built {
        final List<VerificationMethodEntry> vms = new ArrayList<>();
        final List<String> authentication = new ArrayList<>();
        final List<String> assertionMethod = new ArrayList<>();
    }
}
