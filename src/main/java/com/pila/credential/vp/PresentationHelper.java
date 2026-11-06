package com.pila.credential.vp;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.util.Rfc3339;
import com.pila.credential.common.util.VCUtil;
import com.pila.credential.common.util.Vcdm;
import com.pila.credential.vc.Credential;
import com.pila.credential.vc.CredentialOptions;
import com.pila.credential.vc.CredentialParser;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public final class PresentationHelper {
    private static final ObjectMapper MAPPER = new ObjectMapper();

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
            vpJSON.put("@context", VCUtil.serializeContexts(vpc.getContext()));
        }
        if (vpc.getId() != null && !vpc.getId().isEmpty()) {
            vpJSON.put("id", vpc.getId());
        }
        if (vpc.getTypes() != null && !vpc.getTypes().isEmpty()) {
            vpJSON.put("type", VCUtil.serializeTypes(vpc.getTypes()));
        }
        if (vpc.getHolder() != null && !vpc.getHolder().isEmpty()) {
            vpJSON.put("holder", vpc.getHolder());
        }
        if (vpc.getValidFrom() != null) {
            vpJSON.put("validFrom", Rfc3339.format(vpc.getValidFrom()));
        }
        if (vpc.getValidUntil() != null) {
            vpJSON.put("validUntil", Rfc3339.format(vpc.getValidUntil()));
        }

        List<Credential> vcs = vpc.getVerifiableCredentials();
        if (vcs != null && !vcs.isEmpty()) {
            List<Object> list = new ArrayList<>();
            for (int i = 0; i < vcs.size(); i++) {
                Credential vc = vcs.get(i);
                if (vc == null) {
                    throw new Exception("credential at index " + i + " is nil");
                }
                try {
                    list.add(vc.serialize());
                } catch (Exception e) {
                    throw new Exception("failed to serialize credential " + i + ": " + e.getMessage(), e);
                }
            }
            vpJSON.put("verifiableCredential", list);
        }
        return vpJSON;
    }

    /**
     * Verifies every embedded credential (single object or array). Fails when there are none, like Go, so a
     * presentation cannot pass VC validation by carrying nothing.
     */
    public static void verifyEmbeddedCredentials(PresentationData data, PresentationOptions options)
            throws Exception {
        Object raw = data.get("verifiableCredential");
        if (raw == null) {
            throw new Exception("failed to verify presentation: credential input is nil");
        }
        List<?> items = raw instanceof List<?> l ? l : List.of(raw);

        CredentialOptions vcOpts = options.getVcOptions() != null ? options.getVcOptions().copyForPresentation()
                : new CredentialOptions();
        // The presentation's resolver and leeway are the defaults; options given to withVCValidation win.
        if (vcOpts.getResolver() == null) {
            vcOpts.setResolver(options.effectiveResolver());
        }
        if (vcOpts.getClockSkewLeewayMs() == 0) {
            vcOpts.setClockSkewLeewayMs(options.getClockSkewLeewayMs());
        }

        for (int i = 0; i < items.size(); i++) {
            Object item = items.get(i);
            if (item == null) {
                throw new Exception("credential at index " + i + " is nil");
            }
            Credential parsed;
            try {
                byte[] bytes = item instanceof String s ? s.getBytes(StandardCharsets.UTF_8)
                        : MAPPER.writeValueAsBytes(item);
                parsed = CredentialParser.parseCredential(bytes);
            } catch (Exception e) {
                throw new Exception("failed to parse credential at index " + i + ": " + e.getMessage(), e);
            }
            try {
                parsed.verify(vcOpts);
            } catch (Exception e) {
                throw new Exception("failed to verify credential at index " + i + ": " + e.getMessage(), e);
            }
        }
    }

    public static void checkExpiration(PresentationData data, long leewayMs) throws Exception {
        Vcdm.checkValidityPeriod("presentation", data.get("validFrom"), data.get("validUntil"), leewayMs);
    }
}
