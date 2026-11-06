package com.pila.credential.did;

import com.pila.credential.common.verificationmethod.DIDDocument;
import com.pila.credential.common.verificationmethod.VerificationMethodEntry;
import com.pila.credential.didv2.did.DIDDocumentOps;

import java.time.Instant;
import java.util.List;

/**
 * Alias kept for existing callers; the implementation lives in {@link DIDDocumentOps}
 * ({@code com.pila.credential.didv2.did}, the home of Go's {@code didv2/did}).
 *
 * @deprecated use {@link DIDDocumentOps}
 */
@Deprecated
public final class VerificationMethodOps {
    public static final String CID_CONTEXT = DIDDocumentOps.CID_CONTEXT;
    public static final String SECP256K1_VM_TYPE = DIDDocumentOps.SECP256K1_VM_TYPE;
    public static final String MULTIKEY_VM_TYPE = DIDDocumentOps.MULTIKEY_VM_TYPE;

    private VerificationMethodOps() {
    }

    public static VerificationMethodEntry findVerificationMethod(DIDDocument doc, String idOrFragment) {
        return DIDDocumentOps.findVerificationMethod(doc, idOrFragment);
    }

    public static String addVerificationMethod(DIDDocument doc, VerificationMethodEntry vm,
            List<VerificationPurpose> purposes) throws Exception {
        return DIDDocumentOps.addVerificationMethod(doc, vm, purposes);
    }

    public static String rotateVerificationMethod(DIDDocument doc, String oldKid, VerificationMethodEntry newVM,
            String reason, Instant revokedAt) throws Exception {
        return DIDDocumentOps.rotateVerificationMethod(doc, oldKid, newVM, reason, revokedAt);
    }

    public static void revokeVerificationMethod(DIDDocument doc, String kid, String reason, Instant revokedAt)
            throws Exception {
        DIDDocumentOps.revokeVerificationMethod(doc, kid, reason, revokedAt);
    }

    public static void addVerificationMethodPurposes(DIDDocument doc, String kid, List<VerificationPurpose> purposes)
            throws Exception {
        DIDDocumentOps.addVerificationMethodPurposes(doc, kid, purposes);
    }

    public static void removeVerificationMethodPurposes(DIDDocument doc, String kid, List<VerificationPurpose> purposes)
            throws Exception {
        DIDDocumentOps.removeVerificationMethodPurposes(doc, kid, purposes);
    }

    public static String canonicalVmId(String did, String idOrFragment) {
        return DIDDocumentOps.canonicalVmId(did, idOrFragment);
    }

    public static String vmTypeFor(VerificationMethodEntry vm) throws Exception {
        return DIDDocumentOps.vmTypeFor(vm);
    }
}
