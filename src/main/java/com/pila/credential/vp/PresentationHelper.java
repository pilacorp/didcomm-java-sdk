package com.pila.credential.vp;

import com.pila.credential.vc.Credential;

import java.util.ArrayList;
import java.util.List;

public final class PresentationHelper {

    private PresentationHelper() {
    }

    public static PresentationData serializePresentationContents(PresentationContents vpc) throws Exception {
        if (vpc == null) {
            throw new IllegalArgumentException("presentation contents is nil");
        }
        if ((vpc.getContext() == null || vpc.getContext().isEmpty())
                && (vpc.getId() == null || vpc.getId().isEmpty())
                && (vpc.getHolder() == null || vpc.getHolder().isEmpty())) {
            throw new Exception("contents must have context, ID, or holder");
        }

        PresentationData vpJSON = new PresentationData();
        if (vpc.getContext() != null && !vpc.getContext().isEmpty()) {
            vpJSON.put("@context", com.pila.credential.common.util.VCUtil.serializeContexts(vpc.getContext()));
        }
        if (vpc.getId() != null && !vpc.getId().isEmpty()) {
            vpJSON.put("id", vpc.getId());
        }
        if (vpc.getTypes() != null && !vpc.getTypes().isEmpty()) {
            vpJSON.put("type", com.pila.credential.common.util.VCUtil.serializeTypes(vpc.getTypes()));
        }
        if (vpc.getHolder() != null && !vpc.getHolder().isEmpty()) {
            vpJSON.put("holder", vpc.getHolder());
        }
        if (vpc.getValidFrom() != null) {
            vpJSON.put("validFrom", vpc.getValidFrom().toString());
        }
        if (vpc.getValidUntil() != null) {
            vpJSON.put("validUntil", vpc.getValidUntil().toString());
        }

        List<Credential> vcs = vpc.getVerifiableCredentials();
        if (vcs != null && !vcs.isEmpty()) {
            List<Object> list = new ArrayList<>();
            for (int i = 0; i < vcs.size(); i++) {
                Credential vc = vcs.get(i);
                if (vc == null) {
                    throw new Exception("credential at index " + i + " is nil");
                }
                Object serialized = vc.serialize();
                list.add(serialized);
                try {
                    vc.verify();
                } catch (Exception e) {
                    throw new Exception("failed to verify credential " + i + ": " + e.getMessage());
                }
            }
            vpJSON.put("verifiableCredential", list);
        }
        return vpJSON;
    }
}
