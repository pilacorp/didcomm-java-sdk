package com.pila.credential.didv2.did;

import com.pila.credential.common.verificationmethod.DIDDocument;
import com.pila.credential.common.verificationmethod.JWK;
import com.pila.credential.common.verificationmethod.RevocationReasons;
import com.pila.credential.common.verificationmethod.VerificationMethodEntry;
import com.pila.credential.did.VerificationPurpose;
import com.pila.credential.didv2.Hex;
import com.pila.credential.didv2.Rfc3339Nano;
import com.pila.credential.didv2.Secp256k1;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

/**
 * DIDv2 verification-method operations, the methods of Go {@code didv2/did.DIDDocument}
 * (verification_method_ops.go). There is no RemoveVerificationMethod. {@code revoked} is written as Go marshals a
 * {@code time.Time} (RFC3339Nano).
 */
public final class DIDDocumentOps {
    public static final String CID_CONTEXT = "https://www.w3.org/ns/cid/v1";
    public static final String SECP256K1_VM_TYPE = "EcdsaSecp256k1VerificationKey2019";
    public static final String MULTIKEY_VM_TYPE = "Multikey";

    private DIDDocumentOps() {
    }

    /** Go DIDDocument.Validate: unique ids, key material matching the type, relationship refs that resolve. */
    public static void validate(DIDDocument doc) throws Exception {
        com.pila.credential.didv2.Documents.validateDIDDocument(doc);
    }

    /** Go DIDDocument.Hash: Keccak-256 of the JCS-canonical document, "0x" + 64 hex. */
    public static String hash(DIDDocument doc) throws Exception {
        return com.pila.credential.didv2.Documents.hashDIDDocument(doc);
    }

    public static VerificationMethodEntry findVerificationMethod(DIDDocument doc, String idOrFragment) {
        if (doc == null || doc.getVerificationMethod() == null) {
            return null;
        }
        String target = canonicalVmId(doc.getId(), idOrFragment);
        for (VerificationMethodEntry vm : doc.getVerificationMethod()) {
            if (canonicalVmId(doc.getId(), vm.getId()).equals(target)) {
                return vm;
            }
        }
        return null;
    }

    public static String addVerificationMethod(DIDDocument doc, VerificationMethodEntry vm,
            List<VerificationPurpose> purposes) throws Exception {
        if (doc == null) {
            throw new Exception("document is nil");
        }
        if (doc.getId() == null || doc.getId().isEmpty()) {
            throw new Exception("document.id is required");
        }
        if (purposes == null) {
            purposes = List.of();
        }
        String expectedType = vmTypeFor(vm);
        validatePurposes(purposes);

        VerificationMethodEntry next = new VerificationMethodEntry();
        next.setId(vm.getId() != null && !vm.getId().isEmpty()
                ? canonicalVmId(doc.getId(), vm.getId())
                : nextSequentialKid(doc));
        next.setType(vm.getType() == null || vm.getType().isEmpty() ? expectedType : vm.getType());
        next.setController(vm.getController() == null || vm.getController().isEmpty() ? doc.getId() : vm.getController());
        next.setPublicKeyHex(vm.getPublicKeyHex());
        next.setPublicKeyMultibase(vm.getPublicKeyMultibase());
        next.setPublicKeyJwk(vm.getPublicKeyJwk());
        next.setRevoked(vm.getRevoked());
        next.setRevocationReason(vm.getRevocationReason());
        if (!expectedType.equals(next.getType())) {
            throw new Exception("verification method type \"" + next.getType()
                    + "\" does not match its key material: expected " + expectedType);
        }
        if (findVerificationMethod(doc, next.getId()) != null) {
            throw new Exception("verification method already exists: " + next.getId());
        }
        String existing = findByKeyFingerprint(doc, keyFingerprint(next));
        if (!existing.isEmpty()) {
            throw new Exception("verification method with the same public key already exists: " + existing);
        }
        mutableVms(doc).add(next);
        if (MULTIKEY_VM_TYPE.equals(next.getType())) {
            ensureContext(doc, CID_CONTEXT);
        }
        for (VerificationPurpose p : purposes) {
            addPurpose(doc, p, next.getId());
        }
        return next.getId();
    }

    public static String rotateVerificationMethod(DIDDocument doc, String oldKid, VerificationMethodEntry newVM,
            String reason, Instant revokedAt) throws Exception {
        return rotateVerificationMethod(doc, oldKid, newVM, reason,
                (revokedAt == null ? Instant.now() : revokedAt).atOffset(java.time.ZoneOffset.UTC));
    }

    public static String rotateVerificationMethod(DIDDocument doc, String oldKid, VerificationMethodEntry newVM,
            String reason, OffsetDateTime revokedAt) throws Exception {
        if (doc == null) {
            throw new Exception("document is nil");
        }
        if (oldKid == null || oldKid.isEmpty()) {
            throw new Exception("old_kid is required");
        }
        VerificationMethodEntry old = findVerificationMethod(doc, oldKid);
        if (old == null) {
            throw new Exception("verification method not found: " + oldKid);
        }
        if (old.getRevoked() != null && !old.getRevoked().isEmpty()) {
            throw new Exception("verification method \"" + old.getId() + "\" is already revoked");
        }
        List<VerificationPurpose> purposes = purposesOfKid(doc, old.getId());
        String newID = addVerificationMethod(doc, newVM, purposes);
        VerificationMethodEntry after = findVerificationMethod(doc, oldKid);
        if (after == null) {
            throw new Exception("verification method index mismatch after append: " + oldKid);
        }
        after.setRevoked(Rfc3339Nano.format(revokedAt == null ? OffsetDateTime.now(java.time.ZoneOffset.UTC) : revokedAt));
        after.setRevocationReason(reason == null || reason.isEmpty() ? RevocationReasons.SUPERSEDED : reason);
        ensureContext(doc, CID_CONTEXT);
        return newID;
    }

    public static void revokeVerificationMethod(DIDDocument doc, String kid, String reason, Instant revokedAt)
            throws Exception {
        revokeVerificationMethod(doc, kid, reason,
                (revokedAt == null ? Instant.now() : revokedAt).atOffset(java.time.ZoneOffset.UTC));
    }

    public static void revokeVerificationMethod(DIDDocument doc, String kid, String reason, OffsetDateTime revokedAt)
            throws Exception {
        if (doc == null) {
            throw new Exception("document is nil");
        }
        if (kid == null || kid.isEmpty()) {
            throw new Exception("kid is required");
        }
        if (reason == null || reason.isEmpty()) {
            throw new Exception("reason is required");
        }
        VerificationMethodEntry vm = findVerificationMethod(doc, kid);
        if (vm == null) {
            throw new Exception("verification method not found: " + kid);
        }
        if (vm.getRevoked() != null && !vm.getRevoked().isEmpty()) {
            throw new Exception("verification method \"" + vm.getId() + "\" is already revoked at "
                    + vm.getRevoked() + " (reason: " + vm.getRevocationReason() + ")");
        }
        OffsetDateTime at = revokedAt == null ? OffsetDateTime.now(java.time.ZoneOffset.UTC) : revokedAt;
        vm.setRevoked(Rfc3339Nano.format(at));
        vm.setRevocationReason(reason);
        ensureContext(doc, CID_CONTEXT);
    }

    public static void addVerificationMethodPurposes(DIDDocument doc, String kid, List<VerificationPurpose> purposes)
            throws Exception {
        if (doc == null) {
            throw new Exception("document is nil");
        }
        if (kid == null || kid.isEmpty()) {
            throw new Exception("kid is required");
        }
        if (purposes == null || purposes.isEmpty()) {
            throw new Exception("purposes is required");
        }
        VerificationMethodEntry vm = findVerificationMethod(doc, kid);
        if (vm == null) {
            throw new Exception("verification method not found: " + kid);
        }
        if (vm.getRevoked() != null && !vm.getRevoked().isEmpty()) {
            throw new Exception("verification method \"" + vm.getId() + "\" is revoked");
        }
        validatePurposes(purposes);
        for (VerificationPurpose p : purposes) {
            addPurpose(doc, p, kid);
        }
    }

    public static void removeVerificationMethodPurposes(DIDDocument doc, String kid, List<VerificationPurpose> purposes)
            throws Exception {
        if (doc == null) {
            throw new Exception("document is nil");
        }
        if (kid == null || kid.isEmpty()) {
            throw new Exception("kid is required");
        }
        if (purposes == null || purposes.isEmpty()) {
            throw new Exception("purposes is required");
        }
        if (findVerificationMethod(doc, kid) == null) {
            throw new Exception("verification method not found: " + kid);
        }
        validatePurposes(purposes);
        for (VerificationPurpose p : purposes) {
            removePurpose(doc, p, kid);
        }
    }

    public static String canonicalVmId(String did, String idOrFragment) {
        if (idOrFragment != null && idOrFragment.startsWith("#")) {
            return did + idOrFragment;
        }
        return idOrFragment;
    }

    public static String vmTypeFor(VerificationMethodEntry vm) throws Exception {
        if (vm.getPublicKeyJwk() != null && !vm.getPublicKeyJwk().isEmpty()) {
            throw new Exception(
                    "publicKeyJwk is not supported: publish secp256k1 as publicKeyHex or P-256 as publicKeyMultibase");
        }
        boolean hasHex = vm.getPublicKeyHex() != null && !vm.getPublicKeyHex().isEmpty();
        boolean hasMultibase = vm.getPublicKeyMultibase() != null && !vm.getPublicKeyMultibase().isEmpty();
        if (hasHex && hasMultibase) {
            throw new Exception("verification method must have publicKeyHex or publicKeyMultibase, not both");
        }
        if (hasHex) {
            return SECP256K1_VM_TYPE;
        }
        if (hasMultibase) {
            return MULTIKEY_VM_TYPE;
        }
        throw new Exception("verification method must have either publicKeyHex or publicKeyMultibase");
    }

    static void ensureContext(DIDDocument doc, String ctx) {
        List<String> context = doc.getContext();
        if (context == null) {
            context = new ArrayList<>();
            doc.setContext(context);
        } else if (!(context instanceof ArrayList)) {
            context = new ArrayList<>(context);
            doc.setContext(context);
        }
        if (!context.contains(ctx)) {
            context.add(ctx);
        }
    }

    private static String findByKeyFingerprint(DIDDocument doc, String fp) {
        if (fp == null || fp.isEmpty() || doc.getVerificationMethod() == null) {
            return "";
        }
        for (VerificationMethodEntry vm : doc.getVerificationMethod()) {
            if (fp.equals(keyFingerprint(vm))) {
                return vm.getId();
            }
        }
        return "";
    }

    private static String keyFingerprint(VerificationMethodEntry vm) {
        if (vm.getPublicKeyHex() != null && !vm.getPublicKeyHex().isEmpty()) {
            return "publicKeyHex:" + normalizeSecp256k1Hex(vm.getPublicKeyHex());
        }
        if (vm.getPublicKeyMultibase() != null && !vm.getPublicKeyMultibase().isEmpty()) {
            return "publicKeyMultibase:" + vm.getPublicKeyMultibase();
        }
        return "";
    }

    private static String normalizeSecp256k1Hex(String h) {
        String trimmed = (h.toLowerCase().startsWith("0x") ? h.toLowerCase().substring(2) : h.toLowerCase());
        try {
            byte[] raw = Hex.decodeGo(trimmed);
            if ((raw.length == 65 && raw[0] == 0x04) || (raw.length == 33 && (raw[0] == 0x02 || raw[0] == 0x03))) {
                return Hex.encode(Secp256k1.compress(raw));
            }
        } catch (RuntimeException e) {
            // not a hex string or not a point on the curve: compared as lowercase hex
        }
        return trimmed;
    }

    private static void validatePurposes(List<VerificationPurpose> purposes) throws Exception {
        for (VerificationPurpose p : purposes) {
            if (p == null) {
                throw new Exception("unsupported purpose: null");
            }
        }
    }

    private static void addPurpose(DIDDocument doc, VerificationPurpose p, String kid) {
        if (p == VerificationPurpose.AUTHENTICATION) {
            doc.setAuthentication(addRefNormalized(doc.getAuthentication(), kid, doc.getId()));
        } else {
            doc.setAssertionMethod(addRefNormalized(doc.getAssertionMethod(), kid, doc.getId()));
        }
    }

    private static void removePurpose(DIDDocument doc, VerificationPurpose p, String kid) {
        if (p == VerificationPurpose.AUTHENTICATION) {
            doc.setAuthentication(removeRefNormalized(doc.getAuthentication(), kid, doc.getId()));
        } else {
            doc.setAssertionMethod(removeRefNormalized(doc.getAssertionMethod(), kid, doc.getId()));
        }
    }

    private static List<String> addRefNormalized(List<String> arr, String kid, String did) {
        String target = canonicalVmId(did, kid);
        LinkedHashSet<String> seen = new LinkedHashSet<>();
        List<String> out = new ArrayList<>();
        if (arr != null) {
            for (String x : arr) {
                String c = canonicalVmId(did, x);
                if (seen.add(c)) {
                    out.add(c);
                }
            }
        }
        if (seen.add(target)) {
            out.add(target);
        }
        return out;
    }

    private static List<String> removeRefNormalized(List<String> arr, String kid, String did) {
        String target = canonicalVmId(did, kid);
        LinkedHashSet<String> seen = new LinkedHashSet<>();
        List<String> out = new ArrayList<>();
        if (arr != null) {
            for (String x : arr) {
                String c = canonicalVmId(did, x);
                if (c.equals(target) || !seen.add(c)) {
                    continue;
                }
                out.add(c);
            }
        }
        return out;
    }

    private static List<VerificationPurpose> purposesOfKid(DIDDocument doc, String kid) {
        List<VerificationPurpose> out = new ArrayList<>();
        if (containsKidRef(doc.getAuthentication(), kid, doc.getId())) {
            out.add(VerificationPurpose.AUTHENTICATION);
        }
        if (containsKidRef(doc.getAssertionMethod(), kid, doc.getId())) {
            out.add(VerificationPurpose.ASSERTION_METHOD);
        }
        return out;
    }

    private static boolean containsKidRef(List<String> arr, String kid, String did) {
        if (arr == null) {
            return false;
        }
        String target = canonicalVmId(did, kid);
        for (String x : arr) {
            if (canonicalVmId(did, x).equals(target)) {
                return true;
            }
        }
        return false;
    }

    private static String nextSequentialKid(DIDDocument doc) {
        long maxN = 0;
        if (doc.getVerificationMethod() != null) {
            for (VerificationMethodEntry vm : doc.getVerificationMethod()) {
                String frag = vm.getId() != null && vm.getId().startsWith(doc.getId())
                        ? vm.getId().substring(doc.getId().length())
                        : vm.getId();
                if (frag == null || !frag.startsWith("#key-")) {
                    continue;
                }
                String num = frag.substring("#key-".length());
                if (!num.matches("[+-]?[0-9]+")) {
                    continue;
                }
                try {
                    long n = Long.parseLong(num);
                    if (n > maxN) {
                        maxN = n;
                    }
                } catch (NumberFormatException ignored) {
                    // strconv.Atoi range error: skipped
                }
            }
        }
        return doc.getId() + "#key-" + (maxN + 1);
    }

    private static List<VerificationMethodEntry> mutableVms(DIDDocument doc) {
        List<VerificationMethodEntry> vms = doc.getVerificationMethod();
        if (vms == null) {
            vms = new ArrayList<>();
            doc.setVerificationMethod(vms);
        } else if (!(vms instanceof ArrayList)) {
            vms = new ArrayList<>(vms);
            doc.setVerificationMethod(vms);
        }
        return vms;
    }
}
