package com.pila.credential.common.verificationmethod;

import java.time.Instant;
import java.util.List;

/**
 * Post-crypto checks for proof purpose and VM revocation (go-credential-sdk parity).
 */
public final class StrictPurposeCheck {

    private StrictPurposeCheck() {
    }

    public static void enforce(DIDDocument doc, VerificationMethodEntry vm, String proofPurpose, String proofCreated)
            throws Exception {
        if (vm == null) {
            throw new Exception("verification method entry is required");
        }
        if (RevocationReasons.isHardRevocationReason(vm.getRevocationReason())) {
            throw new Exception(String.format(
                    "verification method '%s' revoked with hard reason '%s'",
                    vm.getId(), vm.getRevocationReason()));
        }
        if (vm.getRevoked() != null && !vm.getRevoked().isEmpty()) {
            Instant created = Instant.parse(proofCreated);
            Instant revoked = Instant.parse(vm.getRevoked());
            if (!created.isBefore(revoked)) {
                throw new Exception(String.format(
                        "verification method '%s' was revoked at %s; proof.created %s is not earlier",
                        vm.getId(), revoked, created));
            }
        }
        List<String> arr;
        if ("authentication".equals(proofPurpose)) {
            arr = doc.getAuthentication();
        } else if ("assertionMethod".equals(proofPurpose)) {
            arr = doc.getAssertionMethod();
        } else {
            throw new Exception("unsupported proofPurpose '" + proofPurpose + "'");
        }
        if (!idInArray(vm.getId(), doc.getId(), arr)) {
            throw new Exception(String.format(
                    "verification method '%s' is not granted purpose '%s' on DID '%s'",
                    vm.getId(), proofPurpose, doc.getId()));
        }
    }

    private static boolean idInArray(String vmId, String docId, List<String> arr) {
        if (arr == null) {
            return false;
        }
        String frag = vmId;
        if (vmId.startsWith(docId + "#")) {
            frag = vmId.substring(docId.length());
        }
        for (String ref : arr) {
            if (ref.equals(vmId) || ref.equals(frag)) {
                return true;
            }
        }
        return false;
    }
}
