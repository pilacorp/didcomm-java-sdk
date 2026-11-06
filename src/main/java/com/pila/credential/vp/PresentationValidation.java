package com.pila.credential.vp;

import com.pila.credential.common.error.CredentialException;
import com.pila.credential.common.util.Vcdm;

import java.util.Map;

/** Checks shared by the JWT and JOSE presentation types. */
final class PresentationValidation {
    private PresentationValidation() {
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> asMap(Object o) {
        return (Map<String, Object>) o;
    }

    /** A JWT holds one signature; a second would replace it, so it is refused unless withReplaceProof. */
    static void refuseOverwrite(String current, PresentationOptions o) throws CredentialException {
        if (current == null || current.isEmpty() || o.isReplaceProof()) {
            return;
        }
        throw new CredentialException(CredentialException.Code.ALREADY_SIGNED,
                "presentation is already signed; signing again would replace that signature — "
                        + "pass withReplaceProof to do so deliberately");
    }

    /** The payload really is the VC 2.0 presentation its vp+jwt media type claims. */
    static void requireJOSEPresentation(Map<String, Object> m) throws Exception {
        String first = Vcdm.firstContext(m.get("@context"));
        if (!Vcdm.CONTEXT_V2.equals(first)) {
            throw new Exception(JOSEPresentation.TYPE_VP_JWT + " payload must name \"" + Vcdm.CONTEXT_V2
                    + "\" first in @context, got \"" + first + "\"");
        }
        if (!Vcdm.hasType(m.get("type"), "VerifiablePresentation")) {
            throw new Exception(JOSEPresentation.TYPE_VP_JWT + " payload must have type VerifiablePresentation");
        }
    }
}
