package com.pila.credential.vp;

public final class PresentationAudience {

    private PresentationAudience() {
    }

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

    public static void checkAudience(Object aud, PresentationOptions options) throws Exception {
        if (options == null) {
            return;
        }
        if (options.getExpectedDomain() != null && !options.getExpectedDomain().isEmpty()) {
            if (!audContains(aud, options.getExpectedDomain())) {
                throw new Exception("aud " + aud + " does not match expected domain "
                        + options.getExpectedDomain());
            }
            return;
        }
        if (options.isRequireAudience()) {
            throw new Exception("WithRequireAudience needs WithExpectedDomain");
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
