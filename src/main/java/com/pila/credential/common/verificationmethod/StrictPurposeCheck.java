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

    private static final java.util.regex.Pattern RFC3339 = java.util.regex.Pattern.compile(
            "\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[+-]\\d{2}:\\d{2})");

    /** Go's {@code time.Parse(time.RFC3339, s)}: upper-case T and Z only, no leap second. */
    static Instant parseRfc3339(String s, String what) throws Exception {
        if (s == null || !RFC3339.matcher(s).matches()) {
            throw new Exception("invalid " + what + " timestamp '" + s + "': not RFC 3339");
        }
        try {
            return java.time.OffsetDateTime.parse(s).toInstant();
        } catch (java.time.format.DateTimeParseException e) {
            throw new Exception("invalid " + what + " timestamp '" + s + "': " + e.getMessage(), e);
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
