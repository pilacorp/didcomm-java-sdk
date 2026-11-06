package com.pila.credential.common.verificationmethod;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

public final class ResolveVmUrl {
    private ResolveVmUrl() {
    }

    public static String normalizeVerificationMethodURL(String did, String kid) {
        if (kid == null || kid.isEmpty()) {
            return "";
        }
        if (kid.startsWith("did:")) {
            return kid;
        }
        if (kid.startsWith("#")) {
            return did + kid;
        }
        return did + "#" + kid;
    }

    /**
     * Go ResolveVerificationMethodURLForKey: the id of the latest active VM whose key matches {@code kind}, so the
     * resolved VM is compatible with the signer's cryptosuite.
     */
    public static String resolveVerificationMethodURLForKey(String did, String purpose,
            VerificationMethodKeyKind kind, DocumentResolver resolver) throws Exception {
        if (resolver == null) {
            throw new Exception("document resolver is not configured");
        }
        DIDDocument doc;
        try {
            doc = resolver.resolveDocument(did);
        } catch (Exception e) {
            throw new Exception("failed to resolve DID '" + did + "': " + e.getMessage(), e);
        }
        return Selector.selectLatestActiveVMForKey(doc, purpose, kind).getId();
    }

    public static SigningVM resolveSigningVM(String did, String purpose, String pinnedKid, DocumentResolver resolver)
            throws Exception {
        if (resolver == null) {
            throw new Exception("document resolver is not configured");
        }
        String url = normalizeVerificationMethodURL(did, pinnedKid == null ? "" : pinnedKid);
        String vmDID = didFromVMURL(url);
        if (vmDID.isEmpty()) {
            vmDID = did;
        }
        DIDDocument doc = resolver.resolveDocument(vmDID);
        VerificationMethodEntry vm;
        if (pinnedKid != null && !pinnedKid.isEmpty()) {
            vm = findExact(doc, url);
        } else {
            vm = Selector.selectDefaultSigningVM(doc, purpose);
        }
        // Go rejects only on `revoked`; a hard reason without `revoked` is a verify-time concern.
        if (vm.getRevoked() != null && !vm.getRevoked().isEmpty()) {
            throw new Exception("verification method '" + vm.getId() + "' was revoked at "
                    + rfc3339UTC(vm.getRevoked()));
        }
        Selector.ensureVMAuthorizedForPurpose(doc, vm.getId(), purpose);
        return new SigningVM(vm, vm.getId());
    }

    private static VerificationMethodEntry findExact(DIDDocument doc, String vmURL) throws Exception {
        if (doc == null) {
            throw new Exception("did document is nil");
        }
        if (vmURL == null || vmURL.isEmpty()) {
            throw new Exception("verification method is empty");
        }
        if (doc.getVerificationMethod() != null) {
            for (VerificationMethodEntry vm : doc.getVerificationMethod()) {
                if (vmURL.equals(vm.getId())) {
                    return vm;
                }
            }
        }
        throw new Exception("verification method '" + vmURL + "' not found in DID '" + doc.getId() + "' document");
    }

    private static String didFromVMURL(String url) {
        if (url == null || !url.startsWith("did:")) {
            return "";
        }
        int i = url.indexOf('#');
        return i > 0 ? url.substring(0, i) : url;
    }

    private static String rfc3339UTC(String revoked) {
        try {
            return DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'")
                    .format(OffsetDateTime.parse(revoked).withOffsetSameInstant(ZoneOffset.UTC));
        } catch (Exception e) {
            return revoked;
        }
    }

    public record SigningVM(VerificationMethodEntry vm, String url) {
    }
}
