package com.pila.credential.didv2;

/** Go did.DIDType: the kind of DID being issued. */
public enum DIDType {
    PEOPLE(Types.DID_TYPE_PEOPLE),
    ITEM(Types.DID_TYPE_ITEM),
    LOCATION(Types.DID_TYPE_LOCATION),
    ACTIVITY(Types.DID_TYPE_ACTIVITY);

    public final int value;

    DIDType(int value) {
        this.value = value;
    }

    /** Go DIDType.String(): "people", "item", "location", "activity". */
    public String label() {
        return Types.didTypeString(value);
    }
}
