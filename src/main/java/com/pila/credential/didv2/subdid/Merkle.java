package com.pila.credential.didv2.subdid;

import com.pila.credential.didv2.Hex;
import com.pila.credential.didv2.Keccak256;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class Merkle {
    public static final int MAX_LEAVES = 8192;
    private static final int MAX_PROOF_LEN = 13;
    private static final byte[] REVOKED_TAG = "revoked".getBytes(StandardCharsets.UTF_8);

    private Merkle() {
    }

    public static byte[] merkleRoot(List<byte[]> leaves) throws Exception {
        checkLeafCount(leaves.size());
        List<byte[]> level = copy(leaves);
        while (level.size() > 1) {
            level = nextLevel(level);
        }
        return level.get(0);
    }

    public static List<byte[]> merkleProof(List<byte[]> leaves, int index) throws Exception {
        checkLeafCount(leaves.size());
        if (index < 0 || index >= leaves.size()) {
            throw new Exception("subdid: leaf index " + index + " out of range [0, " + leaves.size() + ")");
        }
        List<byte[]> proof = new ArrayList<>();
        List<byte[]> level = copy(leaves);
        int i = index;
        while (level.size() > 1) {
            int sibling = i ^ 1;
            if (sibling < level.size()) {
                proof.add(level.get(sibling));
            }
            level = nextLevel(level);
            i = i / 2;
        }
        return proof;
    }

    public static boolean verifyProof(byte[] leaf, List<byte[]> path, byte[] root) {
        // Go takes [32]byte values; a wrong-size input has no Go equivalent and is refused, not padded or cut
        require32(leaf, "leaf");
        require32(root, "root");
        for (byte[] sibling : path) {
            require32(sibling, "sibling");
        }
        if (path.size() > MAX_PROOF_LEN) {
            return false;
        }
        byte[] h = Arrays.copyOf(leaf, 32);
        for (byte[] sibling : path) {
            h = hashPair(h, sibling);
        }
        return Arrays.equals(h, root);
    }

    public static byte[] revokedLeaf(String addr) {
        if (!com.pila.credential.didv2.Issuer.isAddress(addr)) {
            throw new IllegalArgumentException("subdid: " + addr + " is not a 20-byte address");
        }
        byte[] a = Hex.decode(addr);
        return Keccak256.hash(REVOKED_TAG, a);
    }

    private static void require32(byte[] b, String what) {
        if (b == null || b.length != 32) {
            throw new IllegalArgumentException("subdid: " + what + " is " + (b == null ? 0 : b.length)
                    + " bytes, want 32");
        }
    }

    private static void checkLeafCount(int n) throws Exception {
        if (n == 0) {
            throw new Exception("subdid: a tree needs at least one leaf");
        }
        if (n > MAX_LEAVES) {
            throw new Exception("subdid: " + n + " leaves exceed the maximum of " + MAX_LEAVES);
        }
    }

    private static List<byte[]> nextLevel(List<byte[]> level) {
        List<byte[]> next = new ArrayList<>();
        for (int i = 0; i + 1 < level.size(); i += 2) {
            next.add(hashPair(level.get(i), level.get(i + 1)));
        }
        if (level.size() % 2 == 1) {
            next.add(level.get(level.size() - 1));
        }
        return next;
    }

    private static byte[] hashPair(byte[] a, byte[] b) {
        if (compare(a, b) > 0) {
            byte[] t = a;
            a = b;
            b = t;
        }
        return Keccak256.hash(a, b);
    }

    private static int compare(byte[] a, byte[] b) {
        int n = Math.min(a.length, b.length);
        for (int i = 0; i < n; i++) {
            int d = (a[i] & 0xff) - (b[i] & 0xff);
            if (d != 0) {
                return d;
            }
        }
        return a.length - b.length;
    }

    private static List<byte[]> copy(List<byte[]> leaves) throws Exception {
        List<byte[]> out = new ArrayList<>(leaves.size());
        for (byte[] l : leaves) {
            if (l.length != 32) {
                throw new Exception("hash is not 32 bytes");
            }
            out.add(Arrays.copyOf(l, 32));
        }
        return out;
    }
}
