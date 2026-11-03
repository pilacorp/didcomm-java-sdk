package com.pila.credential.common.verificationmethod;

import java.time.Instant;
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
        if (RevocationReasons.isHardRevocationReason(vm.getRevocationReason())) {
            throw new Exception("verification method '" + vm.getId() + "' revoked with hard reason '"
                    + vm.getRevocationReason() + "'");
        }
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
        Instant instant;
        try {
            instant = Instant.parse(revoked);
        } catch (Exception e) {
            try {
                instant = OffsetDateTime.parse(revoked).toInstant();
            } catch (Exception e2) {
                return revoked;
            }
        }
        return DateTimeFormatter.ISO_INSTANT.format(instant.atOffset(ZoneOffset.UTC))
                .replaceAll("\\.\\d{3}Z$", "Z");
    }

    public record SigningVM(VerificationMethodEntry vm, String url) {
    }
}
