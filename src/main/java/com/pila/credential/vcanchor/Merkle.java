package com.pila.credential.vcanchor;

import com.pila.credential.didv2.Keccak256;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Sorted-pair keccak256 tree; leaves are NOT hashed; an odd trailing node pairs with itself. */
public final class Merkle {
    private Merkle() {
    }

    public static byte[] root(List<byte[]> leaves) {
        if (leaves.isEmpty()) {
            throw new IllegalArgumentException("leaves is empty");
        }
        List<byte[]> level = leaves;
        while (level.size() > 1) {
            level = next(level);
        }
        return level.get(0).clone();
    }

    /** Siblings from the leaf up; empty for a single-leaf tree. */
    public static List<byte[]> proof(List<byte[]> leaves, int leafIndex) {
        if (leaves.isEmpty()) {
            throw new IllegalArgumentException("leaves is empty");
        }
        if (leafIndex < 0 || leafIndex >= leaves.size()) {
            throw new IllegalArgumentException("leaf index " + leafIndex + " out of range");
        }
        List<byte[]> proof = new ArrayList<>();
        int index = leafIndex;
        List<byte[]> level = leaves;
        while (level.size() > 1) {
            int sibling = index ^ 1;
            if (sibling >= level.size()) {
                sibling = index;
            }
            proof.add(level.get(sibling).clone());
            level = next(level);
            index /= 2;
        }
        return proof;
    }

    public static boolean verify(byte[] leaf, List<byte[]> proof, byte[] root) {
        byte[] cur = leaf.clone();
        for (byte[] sibling : proof) {
            cur = mergeSorted(cur, sibling);
        }
        return MessageDigest.isEqual(cur, root);
    }

    public static byte[] mergeSorted(byte[] left, byte[] right) {
        return Arrays.compareUnsigned(left, right) < 0 ? Keccak256.hash(left, right) : Keccak256.hash(right, left);
    }

    /** keccak256 over the concatenated leaves. */
    public static byte[] digestLeaves(List<byte[]> leaves) {
        return Keccak256.hash(leaves.toArray(new byte[0][]));
    }

    /** Siblings a leaf carries in a tree of leafCount leaves: ceil(log2(leafCount)). */
    public static int proofLen(int leafCount) {
        return leafCount <= 1 ? 0 : 32 - Integer.numberOfLeadingZeros(leafCount - 1);
    }

    private static List<byte[]> next(List<byte[]> level) {
        List<byte[]> next = new ArrayList<>((level.size() + 1) / 2);
        for (int i = 0; i < level.size(); i += 2) {
            byte[] right = i + 1 < level.size() ? level.get(i + 1) : level.get(i);
            next.add(mergeSorted(level.get(i), right));
        }
        return next;
    }
}
