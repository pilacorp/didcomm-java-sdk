package com.pila.credential.common.verificationmethod;

import java.util.List;

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
        int bestN = -1;
        if (doc.getVerificationMethod() != null) {
            for (VerificationMethodEntry vm : doc.getVerificationMethod()) {
                if (vm.getRevoked() != null && !vm.getRevoked().isEmpty()) {
                    continue;
                }
                if (!idInPurposeArray(vm.getId(), doc.getId(), purposeArr)) {
                    continue;
                }
                Integer n = parseSequentialFragment(vm.getId(), doc.getId());
                int idx = n == null ? 0 : n;
                if (idx > bestN) {
                    bestN = idx;
                    bestVM = vm;
                }
            }
        }
        if (bestVM == null) {
            throw new Exception("no active verification method for purpose '" + purpose + "' on DID '" + doc.getId()
                    + "'");
        }
        return bestVM;
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

    private static Integer parseSequentialFragment(String vmID, String did) {
        String prefix = did + "#key-";
        if (!vmID.startsWith(prefix)) {
            return null;
        }
        String tail = vmID.substring(prefix.length());
        try {
            int n = Integer.parseInt(tail);
            if (!String.valueOf(n).equals(tail)) {
                return null;
            }
            return n;
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
