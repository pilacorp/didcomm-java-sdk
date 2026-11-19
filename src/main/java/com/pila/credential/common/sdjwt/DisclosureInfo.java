package com.pila.credential.common.sdjwt;

final class DisclosureInfo {
    final String raw;
    final String salt;
    final String objectField;
    final Object value;
    final boolean isArrayElem;

    DisclosureInfo(String raw, String salt, String objectField, Object value, boolean isArrayElem) {
        this.raw = raw;
        this.salt = salt;
        this.objectField = objectField;
        this.value = value;
        this.isArrayElem = isArrayElem;
    }
}
