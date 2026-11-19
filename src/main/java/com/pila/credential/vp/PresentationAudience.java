package com.pila.credential.vp;

import com.pila.credential.common.error.AudienceUnboundException;
import com.pila.credential.common.error.CredentialException;

public final class PresentationAudience {

    private PresentationAudience() {
    }

    /** RFC 7519 4.1.3: aud is a string or an array of strings. */
    public static boolean audContains(Object aud, String domain) {
        if (domain == null) {
            return false;
        }
        if (aud instanceof String s) {
            return domain.equals(s);
        }
        if (aud instanceof Iterable<?> list) {
            for (Object item : list) {
                if (item instanceof String s && domain.equals(s)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Naming this verifier is what checks the audience. {@code withRequireAudience} alone (no expected domain) is
     * refused with {@link AudienceUnboundException}.
     */
    public static void checkAudience(Object aud, PresentationOptions options) throws CredentialException {
        if (options == null) {
            return;
        }
        if (options.getExpectedDomain() != null && !options.getExpectedDomain().isEmpty()) {
            if (!audContains(aud, options.getExpectedDomain())) {
                throw new CredentialException(CredentialException.Code.INVALID_PROOF,
                        "aud " + aud + " does not match expected domain " + options.getExpectedDomain());
            }
            return;
        }
        if (options.isRequireAudience()) {
            throw new AudienceUnboundException();
        }
    }

    public static void checkChallenge(Object actual, String expected) throws Exception {
        if (expected == null || expected.isEmpty()) {
            return;
        }
        if (!expected.equals(actual)) {
            throw new Exception("nonce " + actual + " does not match expected challenge " + expected);
        }
    }
}
