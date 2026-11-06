package com.pila.credential.vp;

/**
 * Consumer-facing presentation contract: read, verify and output (Go {@code vp.Presentation}). Signing lives on
 * the concrete types.
 */
public interface Presentation {
    default void verify() throws Exception {
        verify(null);
    }

    void verify(PresentationOptions opts) throws Exception;

    /** The token String (JWT / JOSE) or the Map with proof (JSON). */
    Object serialize() throws Exception;

    byte[] getContents() throws Exception;

    /** "JSON", "JWT" or "JOSE". */
    String getType();

    /** Field by dot-notation path, or null when absent. */
    Object extractField(String path);
}
