package com.pila.credential.common.verificationmethod;

import java.util.List;
import java.util.function.Predicate;

public final class Selector {
    private Selector() {
    }

    public static VerificationMethodEntry selectDefaultSigningVM(DIDDocument doc, String purpose) throws Exception {
        if (doc == null) {
            throw new Exception("did document is nil");
        }
        if (doc.getVerificationMethod() != null && doc.getVerificationMethod().size() == 1) {
            return doc.getVerificationMethod().get(0);
        }
        return selectLatestActiveVMForPurpose(doc, purpose);
    }

    public static void ensureVMAuthorizedForPurpose(DIDDocument doc, String vmID, String purpose) throws Exception {
        if (doc == null) {
            throw new Exception("did document is nil");
        }
        List<String> arr;
        if ("authentication".equals(purpose)) {
            arr = doc.getAuthentication();
        } else if ("assertionMethod".equals(purpose)) {
            arr = doc.getAssertionMethod();
        } else {
            throw new Exception("unsupported purpose '" + purpose + "'");
        }
        if (!idInPurposeArray(vmID, doc.getId(), arr)) {
            throw new Exception("verification method '" + vmID + "' is not granted purpose '" + purpose
                    + "' on DID '" + doc.getId() + "'");
        }
    }

    public static VerificationMethodEntry selectLatestActiveVMForPurpose(DIDDocument doc, String purpose)
            throws Exception {
        VerificationMethodEntry vm = selectLatestActiveVM(doc, purpose, null);
        if (vm == null) {
            throw new Exception("no active verification method for purpose '" + purpose + "' on DID '" + doc.getId()
                    + "'");
        }
        return vm;
    }

    /**
     * Like {@link #selectLatestActiveVMForPurpose} but only considers verification methods holding a key of
     * {@code kind} (Go SelectLatestActiveVMForKey).
     */
    public static VerificationMethodEntry selectLatestActiveVMForKey(DIDDocument doc, String purpose,
            VerificationMethodKeyKind kind) throws Exception {
        VerificationMethodEntry vm = selectLatestActiveVM(doc, purpose, kind::matches);
        if (vm == null) {
            throw new Exception("no active " + kind.label() + " verification method for purpose '" + purpose
                    + "' on DID '" + doc.getId() + "'");
        }
        return vm;
    }

    /**
     * Go SelectVMForPurpose: an explicit {@code kid} (full URL, "#key-1" or "key-1") is looked up by id and may be
     * revoked (callers apply revocation and purpose checks); an empty kid falls back to the latest active VM.
     */
    public static VerificationMethodEntry selectVMForPurpose(DIDDocument doc, String purpose, String kid)
            throws Exception {
        if (kid == null || kid.isEmpty()) {
            return selectLatestActiveVMForPurpose(doc, purpose);
        }
        if (doc == null) {
            throw new Exception("did document is nil");
        }
        String canonicalKid = ResolveVmUrl.normalizeVerificationMethodURL(doc.getId(), kid);
        if (doc.getVerificationMethod() != null) {
            for (VerificationMethodEntry vm : doc.getVerificationMethod()) {
                if (canonicalKid.equals(vm.getId())) {
                    return vm;
                }
            }
        }
        throw new Exception("verification method '" + kid + "' not found in DID '" + doc.getId() + "' document");
    }

    private static VerificationMethodEntry selectLatestActiveVM(DIDDocument doc, String purpose,
            Predicate<VerificationMethodEntry> match) throws Exception {
        if (doc == null) {
            throw new Exception("did document is nil");
        }
        List<String> purposeArr;
        if ("authentication".equals(purpose)) {
            purposeArr = doc.getAuthentication();
        } else if ("assertionMethod".equals(purpose)) {
            purposeArr = doc.getAssertionMethod();
        } else {
            throw new Exception("unsupported purpose: " + purpose);
        }
        if (purposeArr == null || purposeArr.isEmpty()) {
            throw new Exception("no verification methods listed for purpose '" + purpose + "' on DID '" + doc.getId()
                    + "'");
        }
        VerificationMethodEntry bestVM = null;
        long bestN = -1;
        if (doc.getVerificationMethod() != null) {
            for (VerificationMethodEntry vm : doc.getVerificationMethod()) {
                if (vm.getRevoked() != null && !vm.getRevoked().isEmpty()) {
                    continue;
                }
                if (!idInPurposeArray(vm.getId(), doc.getId(), purposeArr)) {
                    continue;
                }
                if (match != null && !match.test(vm)) {
                    continue;
                }
                Long n = parseSequentialFragment(vm.getId(), doc.getId());
                long idx = n == null ? 0 : n;
                // Higher #key-N wins; a tie goes to the larger id (byte order, like Go) so selection does not
                // depend on the resolver's ordering.
                if (idx > bestN || (idx == bestN && bestVM != null && compareBytes(vm.getId(), bestVM.getId()) > 0)) {
                    bestN = idx;
                    bestVM = vm;
                }
            }
        }
        return bestVM;
    }

    private static int compareBytes(String a, String b) {
        return java.util.Arrays.compareUnsigned(a.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                b.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    public static boolean idInPurposeArray(String vmID, String did, List<String> arr) {
        if (arr == null) {
            return false;
        }
        String frag = vmID;
        if (vmID.startsWith(did + "#")) {
            frag = vmID.substring(did.length());
        }
        for (String ref : arr) {
            if (ref.equals(vmID) || ref.equals(frag)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Go parseSequentialFragment: {@code fmt.Sscanf(tail, "%d", &n)}, so "key-01" is 1 and "key-3x" is 3; the
     * tail needs a leading (optionally signed) decimal that fits an int64.
     */
    static Long parseSequentialFragment(String vmID, String did) {
        String prefix = did + "#key-";
        if (vmID == null || !vmID.startsWith(prefix)) {
            return null;
        }
        String tail = vmID.substring(prefix.length());
        int i = 0;
        while (i < tail.length() && (tail.charAt(i) == ' ' || tail.charAt(i) == '\t' || tail.charAt(i) == '\r')) {
            i++;
        }
        int start = i;
        if (i < tail.length() && (tail.charAt(i) == '+' || tail.charAt(i) == '-')) {
            i++;
        }
        int digits = i;
        while (i < tail.length() && tail.charAt(i) >= '0' && tail.charAt(i) <= '9') {
            i++;
        }
        if (i == digits) {
            return null;
        }
        try {
            return Long.parseLong(tail.substring(start, i).replaceFirst("^\\+", ""));
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
