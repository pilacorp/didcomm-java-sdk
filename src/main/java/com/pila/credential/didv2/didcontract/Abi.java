package com.pila.credential.didv2.didcontract;

import com.pila.credential.didv2.Hex;
import com.pila.credential.didv2.Keccak256;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class Abi {
    private Abi() {
    }

    public static byte[] selector(String signature) {
        byte[] hash = Keccak256.hash(signature.getBytes(StandardCharsets.UTF_8));
        return Arrays.copyOf(hash, 4);
    }

    public static byte[] encodeHeadTail(byte[] selector, List<byte[]> words) {
        byte[] out = new byte[selector.length + words.size() * 32];
        System.arraycopy(selector, 0, out, 0, selector.length);
        int o = selector.length;
        for (byte[] w : words) {
            System.arraycopy(pad32(w), 0, out, o, 32);
            o += 32;
        }
        return out;
    }

    public static byte[] pad32(byte[] v) {
        if (v.length == 32) {
            return v;
        }
        if (v.length > 32) {
            return java.util.Arrays.copyOfRange(v, v.length - 32, v.length);
        }
        byte[] out = new byte[32];
        System.arraycopy(v, 0, out, 32 - v.length, v.length);
        return out;
    }

    public static byte[] addressWord(String addr) {
        return pad32(Hex.decode(addr));
    }

    public static byte[] uintWord(int v) {
        return pad32(new byte[] { (byte) v });
    }

    public static byte[] uintWord(BigInteger v) {
        return pad32(v.toByteArray());
    }

    public static byte[] bytes32Word(String hex) {
        byte[] b = Hex.decode(hex);
        if (b.length != 32) {
            throw new IllegalArgumentException("length must be 32 bytes, got " + b.length);
        }
        return b;
    }

    public static List<WriterAnchor> decodeWriterLog(String writerTopic, byte[] data) {
        String writer = "0x" + writerTopic.substring(writerTopic.length() - 40).toLowerCase();
        BigInteger[] offsets = new BigInteger[3];
        for (int i = 0; i < 3; i++) {
            offsets[i] = new BigInteger(1, Arrays.copyOfRange(data, i * 32, (i + 1) * 32));
        }
        List<String> dids = decodeAddressArray(data, offsets[0].intValue());
        List<BigInteger> indexes = decodeUintArray(data, offsets[1].intValue());
        List<String> roots = decodeBytes32Array(data, offsets[2].intValue());
        if (dids.size() != indexes.size() || dids.size() != roots.size()) {
            throw new IllegalArgumentException("BatchSubtreesAnchoredByWriter arrays have lengths "
                    + dids.size() + ", " + indexes.size() + " and " + roots.size());
        }
        List<WriterAnchor> out = new ArrayList<>();
        for (int i = 0; i < dids.size(); i++) {
            WriterAnchor a = new WriterAnchor();
            a.writer = writer;
            a.did = dids.get(i);
            a.treeIndex = indexes.get(i);
            a.root = roots.get(i);
            out.add(a);
        }
        return out;
    }

    public static byte[] encodeWriterLogData(List<String> dids, List<BigInteger> treeIndexes, List<String> roots) {
        int n = dids.size();
        byte[] head = new byte[96];
        System.arraycopy(pad32(BigInteger.valueOf(96).toByteArray()), 0, head, 0, 32);
        int off1 = 96 + 32 + n * 32;
        System.arraycopy(pad32(BigInteger.valueOf(off1).toByteArray()), 0, head, 32, 32);
        int off2 = off1 + 32 + n * 32;
        System.arraycopy(pad32(BigInteger.valueOf(off2).toByteArray()), 0, head, 64, 32);
        byte[] a0 = encodeAddressArray(dids);
        byte[] a1 = encodeUintArray(treeIndexes);
        byte[] a2 = encodeBytes32Array(roots);
        byte[] out = new byte[head.length + a0.length + a1.length + a2.length];
        System.arraycopy(head, 0, out, 0, head.length);
        System.arraycopy(a0, 0, out, head.length, a0.length);
        System.arraycopy(a1, 0, out, head.length + a0.length, a1.length);
        System.arraycopy(a2, 0, out, head.length + a0.length + a1.length, a2.length);
        return out;
    }

    private static byte[] encodeAddressArray(List<String> dids) {
        byte[] out = new byte[32 + dids.size() * 32];
        System.arraycopy(pad32(BigInteger.valueOf(dids.size()).toByteArray()), 0, out, 0, 32);
        for (int i = 0; i < dids.size(); i++) {
            System.arraycopy(addressWord(dids.get(i)), 0, out, 32 + i * 32, 32);
        }
        return out;
    }

    private static byte[] encodeUintArray(List<BigInteger> vals) {
        byte[] out = new byte[32 + vals.size() * 32];
        System.arraycopy(pad32(BigInteger.valueOf(vals.size()).toByteArray()), 0, out, 0, 32);
        for (int i = 0; i < vals.size(); i++) {
            System.arraycopy(uintWord(vals.get(i)), 0, out, 32 + i * 32, 32);
        }
        return out;
    }

    private static byte[] encodeBytes32Array(List<String> roots) {
        byte[] out = new byte[32 + roots.size() * 32];
        System.arraycopy(pad32(BigInteger.valueOf(roots.size()).toByteArray()), 0, out, 0, 32);
        for (int i = 0; i < roots.size(); i++) {
            System.arraycopy(bytes32Word(roots.get(i)), 0, out, 32 + i * 32, 32);
        }
        return out;
    }

    private static List<String> decodeAddressArray(byte[] data, int offset) {
        int n = new BigInteger(1, Arrays.copyOfRange(data, offset, offset + 32)).intValue();
        List<String> out = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            byte[] w = Arrays.copyOfRange(data, offset + 32 + i * 32, offset + 64 + i * 32);
            out.add(Hex.encode0x(Arrays.copyOfRange(w, 12, 32)).toLowerCase());
        }
        return out;
    }

    private static List<BigInteger> decodeUintArray(byte[] data, int offset) {
        int n = new BigInteger(1, Arrays.copyOfRange(data, offset, offset + 32)).intValue();
        List<BigInteger> out = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            out.add(new BigInteger(1, Arrays.copyOfRange(data, offset + 32 + i * 32, offset + 64 + i * 32)));
        }
        return out;
    }

    private static List<String> decodeBytes32Array(byte[] data, int offset) {
        int n = new BigInteger(1, Arrays.copyOfRange(data, offset, offset + 32)).intValue();
        List<String> out = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            out.add(Hex.encode0x(Arrays.copyOfRange(data, offset + 32 + i * 32, offset + 64 + i * 32)).toLowerCase());
        }
        return out;
    }
}
