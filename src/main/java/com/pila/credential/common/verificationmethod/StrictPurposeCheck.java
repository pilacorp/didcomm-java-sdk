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
        if (vm.getRevoked() != null) {
            // Go decodes revoked as *time.Time: "" or anything but RFC 3339 is an error, not "not revoked".
            Instant revoked = parseRfc3339(vm.getRevoked(), "revoked");
            Instant created = parseRfc3339(proofCreated, "proof.created");
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

    /** Go's {@code time.Parse(time.RFC3339, s)}, through the shared parser. */
    static Instant parseRfc3339(String s, String what) throws Exception {
        try {
            return com.pila.credential.common.util.Rfc3339.parse(s);
        } catch (java.time.format.DateTimeParseException e) {
            throw new Exception("invalid " + what + " timestamp '" + s + "': not RFC 3339", e);
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
