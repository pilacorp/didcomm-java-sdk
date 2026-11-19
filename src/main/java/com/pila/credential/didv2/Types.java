package com.pila.credential.didv2;

public final class Types {
    public static final int DID_TYPE_PEOPLE = 0;
    public static final int DID_TYPE_ITEM = 1;
    public static final int DID_TYPE_LOCATION = 2;
    public static final int DID_TYPE_ACTIVITY = 3;

    private Types() {
    }

    public static String didTypeString(int didType) {
        return switch (didType) {
            case DID_TYPE_ITEM -> "item";
            case DID_TYPE_PEOPLE -> "people";
            case DID_TYPE_LOCATION -> "location";
            case DID_TYPE_ACTIVITY -> "activity";
            default -> "unknown";
        };
    }

    public static String toDID(String method, String address) {
        return (method + ":" + address).toLowerCase();
    }
}
