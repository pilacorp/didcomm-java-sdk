package com.pila.credential.common.sdjwt;

/** A decoded disclosure a holder can inspect (Go {@code sdjwt.DecodedDisclosure}). */
public final class DecodedDisclosure {
    public final String disclosure;
    public final String salt;
    public final String fieldName;
    public final Object value;
    public final boolean isArrayElem;

    DecodedDisclosure(String disclosure, DisclosureInfo info) {
        this.disclosure = disclosure;
        this.salt = info.salt;
        this.fieldName = info.objectField;
        this.value = info.value;
        this.isArrayElem = info.isArrayElem;
    }
}
