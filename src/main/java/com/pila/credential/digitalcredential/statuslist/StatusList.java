package com.pila.credential.digitalcredential.statuslist;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Base64;
import java.util.zip.Deflater;
import java.util.zip.InflaterInputStream;
import java.util.zip.DeflaterOutputStream;

/**
 * Token Status List bit helpers (draft-ietf-oauth-status-list). No live HTTP.
 */
public final class StatusList {
    private static final int MAX_LIST_BYTES = 16 << 20;
    private final int bits;
    private final byte[] b;

    private StatusList(int bits, byte[] b) {
        this.bits = bits;
        this.b = b;
    }

    public static StatusList create(int size, int bits) throws Exception {
        if (!validBits(bits)) {
            throw new Exception("statuslist: bits " + bits + ", want 1, 2, 4 or 8");
        }
        if (size < 0 || size > MAX_LIST_BYTES * 8 / bits) {
            throw new Exception("statuslist: size " + size + " out of range for " + bits + "-bit entries");
        }
        return new StatusList(bits, new byte[(size * bits + 7) / 8]);
    }

    public static StatusList fromBytes(byte[] bytes, int bits) throws Exception {
        if (!validBits(bits)) {
            throw new Exception("statuslist: bits " + bits + ", want 1, 2, 4 or 8");
        }
        if (bytes.length > MAX_LIST_BYTES) {
            throw new Exception("statuslist: " + bytes.length + " bytes, want at most " + MAX_LIST_BYTES);
        }
        return new StatusList(bits, Arrays.copyOf(bytes, bytes.length));
    }

    public int bits() {
        return bits;
    }

    public int entries() {
        return b.length * 8 / bits;
    }

    public byte[] bytes() {
        return Arrays.copyOf(b, b.length);
    }

    public int get(int i) throws Exception {
        int[] p = position(i);
        return (b[p[0]] >> p[1]) & mask();
    }

    public void set(int i, int v) throws Exception {
        int[] p = position(i);
        if (v > mask()) {
            throw new Exception("statuslist: value " + v + " does not fit in " + bits + " bits");
        }
        b[p[0]] = (byte) ((b[p[0]] & ~(mask() << p[1])) | (v << p[1]));
    }

    public String encode() throws Exception {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        Deflater def = new Deflater(Deflater.BEST_COMPRESSION);
        try (DeflaterOutputStream out = new DeflaterOutputStream(buf, def)) {
            out.write(b);
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf.toByteArray());
    }

    public static StatusList decode(String lst, int bits) throws Exception {
        if (!validBits(bits)) {
            throw new Exception("statuslist: bits " + bits + ", want 1, 2, 4 or 8");
        }
        byte[] raw = Base64.getUrlDecoder().decode(lst);
        if (raw.length >= 2 && (raw[1] & 0x20) != 0) {
            throw new Exception("statuslist: lst uses a preset dictionary");
        }
        ByteArrayOutputStream inflated = new ByteArrayOutputStream();
        try (InflaterInputStream in = new InflaterInputStream(new ByteArrayInputStream(raw))) {
            byte[] chunk = new byte[4096];
            int n;
            int total = 0;
            while ((n = in.read(chunk)) >= 0) {
                total += n;
                if (total > MAX_LIST_BYTES) {
                    throw new Exception("statuslist: lst inflates past " + MAX_LIST_BYTES + " bytes");
                }
                inflated.write(chunk, 0, n);
            }
        }
        return fromBytes(inflated.toByteArray(), bits);
    }

    private int[] position(int i) throws Exception {
        int n = entries();
        if (i < 0 || i >= n) {
            throw new Exception("statuslist: index " + i + " outside [0, " + n + ")");
        }
        int perByte = 8 / bits;
        return new int[] { i / perByte, (i % perByte) * bits };
    }

    private int mask() {
        return (1 << bits) - 1;
    }

    private static boolean validBits(int bits) {
        return bits == 1 || bits == 2 || bits == 4 || bits == 8;
    }
}
