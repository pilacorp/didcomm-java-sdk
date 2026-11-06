package com.pila.credential.vcanchor;

/** Base for vcanchor failures that Go reports as sentinel errors. */
public class VcAnchorException extends RuntimeException {
    public VcAnchorException(String message) {
        super(message);
    }

    /** Go ErrBatchNotFound. */
    public static class BatchNotFound extends VcAnchorException {
        public BatchNotFound(String message) {
            super(message);
        }

        public BatchNotFound() {
            this("vcanchor: batch not found");
        }
    }

    /** Go ErrBatchConflict: same key, different content. */
    public static class BatchConflict extends VcAnchorException {
        public BatchConflict() {
            super("vcanchor: batch already exists with different content");
        }
    }
}
