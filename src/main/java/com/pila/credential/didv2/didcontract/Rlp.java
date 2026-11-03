package com.pila.credential.didv2.didcontract;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.List;

public final class Rlp {
    private Rlp() {
    }

    public static byte[] encodeList(List<byte[]> encodedItems) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        for (byte[] item : encodedItems) {
            write(body, item);
        }
        byte[] payload = body.toByteArray();
        return prefixList(payload);
    }

    public static byte[] encodeItem(byte[] item) {
        if (item == null || item.length == 0) {
            return new byte[] { (byte) 0x80 };
        }
        if (item.length == 1 && (item[0] & 0xff) < 0x80) {
            return item;
        }
        return prefixString(item);
    }

    public static byte[] encodeUint(BigInteger v) {
        if (v == null || v.signum() == 0) {
            return new byte[] { (byte) 0x80 };
        }
        byte[] raw = v.toByteArray();
        if (raw[0] == 0) {
            byte[] t = new byte[raw.length - 1];
            System.arraycopy(raw, 1, t, 0, t.length);
            raw = t;
        }
        return encodeItem(raw);
    }

    private static byte[] prefixString(byte[] payload) {
        if (payload.length <= 55) {
            byte[] out = new byte[1 + payload.length];
            out[0] = (byte) (0x80 + payload.length);
            System.arraycopy(payload, 0, out, 1, payload.length);
            return out;
        }
        byte[] len = uintBytes(payload.length);
        byte[] out = new byte[1 + len.length + payload.length];
        out[0] = (byte) (0xb7 + len.length);
        System.arraycopy(len, 0, out, 1, len.length);
        System.arraycopy(payload, 0, out, 1 + len.length, payload.length);
        return out;
    }

    private static byte[] prefixList(byte[] payload) {
        if (payload.length <= 55) {
            byte[] out = new byte[1 + payload.length];
            out[0] = (byte) (0xc0 + payload.length);
            System.arraycopy(payload, 0, out, 1, payload.length);
            return out;
        }
        byte[] len = uintBytes(payload.length);
        byte[] out = new byte[1 + len.length + payload.length];
        out[0] = (byte) (0xf7 + len.length);
        System.arraycopy(len, 0, out, 1, len.length);
        System.arraycopy(payload, 0, out, 1 + len.length, payload.length);
        return out;
    }

    private static byte[] uintBytes(int v) {
        if (v == 0) {
            return new byte[] { 0 };
        }
        byte[] raw = BigInteger.valueOf(v).toByteArray();
        if (raw[0] == 0) {
            byte[] t = new byte[raw.length - 1];
            System.arraycopy(raw, 1, t, 0, t.length);
            return t;
        }
        return raw;
    }

    private static void write(ByteArrayOutputStream out, byte[] b) {
        out.write(b, 0, b.length);
    }
}
