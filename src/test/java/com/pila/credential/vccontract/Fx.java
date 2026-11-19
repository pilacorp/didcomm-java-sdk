package com.pila.credential.vccontract;

import com.pila.credential.didv2.Hex;
import com.pila.credential.vccontract.ReceiptSource.Log;
import com.pila.credential.vccontract.ReceiptSource.TxReceipt;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Test fixtures: addresses, synthetic logs for every event shape, stub receipt source. */
final class Fx {
    static final String REGISTRY = "0x1111111111111111111111111111111111111111";
    static final String LEGACY = "0x2222222222222222222222222222222222222222";
    static final String ATTACKER = "0xdead00000000000000000000000000000000beef";
    static final String ISSUER = "0xabc0000000000000000000000000000000000001";
    static final String OTHER = "0xabc0000000000000000000000000000000000002";
    static final int LEGACY_TREE_INDEX = 7;
    static final String ZERO32 = "0x" + "00".repeat(32);

    private Fx() {
    }

    static String leaf(int b) {
        return "0x" + String.format("%02x", b).repeat(32);
    }

    static String pad(String address) {
        return "0x" + "00".repeat(12) + address.substring(2).toLowerCase();
    }

    static String topic(String event) {
        return CredentialRegistry.EVENTS.get(event).topic;
    }

    // ---- minimal ABI encoder (independent of the production decoder) ----
    static byte[] word(BigInteger v) {
        byte[] b = v.toByteArray();
        byte[] out = new byte[32];
        System.arraycopy(b, Math.max(0, b.length - 32), out, 32 - Math.min(32, b.length), Math.min(32, b.length));
        return out;
    }

    static byte[] cat(List<byte[]> parts) {
        int n = parts.stream().mapToInt(p -> p.length).sum();
        byte[] out = new byte[n];
        int o = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, o, p.length);
            o += p.length;
        }
        return out;
    }

    /** Items: a List (dynamic array of 32-byte words given as hex strings or BigIntegers) or a String bytes32. */
    static String encode(Object... args) {
        List<byte[]> head = new ArrayList<>();
        List<byte[]> tail = new ArrayList<>();
        int headSize = args.length * 32;
        int tailSize = 0;
        for (Object a : args) {
            if (a instanceof String s) {
                head.add(Hex.decode(s));
                continue;
            }
            List<?> items = (List<?>) a;
            head.add(word(BigInteger.valueOf(headSize + tailSize)));
            List<byte[]> t = new ArrayList<>();
            t.add(word(BigInteger.valueOf(items.size())));
            for (Object i : items) {
                t.add(i instanceof BigInteger b ? word(b) : Hex.decode((String) i));
            }
            byte[] enc = cat(t);
            tail.add(enc);
            tailSize += enc.length;
        }
        head.addAll(tail);
        return Hex.encode0x(cat(head));
    }

    static Log batchLog(String emitter, List<String> issuers, List<String> roots) {
        return new Log(emitter, List.of(topic("BatchRootsAnchored")), encode(words(issuers), roots));
    }

    static Log singleLog(String emitter, String issuer, String root) {
        return new Log(emitter, List.of(topic("TreeRootAnchored"), pad(issuer), root), "0x");
    }

    static Log issuerBatchLog(String emitter, String issuer, List<String> roots) {
        return new Log(emitter, List.of(topic("IssuerRootsAnchored"), pad(issuer)), encode(roots));
    }

    static Log legacyBatchLog(String emitter, List<String> issuers, List<String> roots) {
        List<BigInteger> idx = new ArrayList<>();
        for (int i = 0; i < roots.size(); i++) {
            idx.add(BigInteger.valueOf(LEGACY_TREE_INDEX + i));
        }
        return new Log(emitter, List.of(topic("BatchTreesUpdated")), encode(words(issuers), idx, roots));
    }

    static Log legacySingleLog(String emitter, String issuer, String root) {
        return new Log(emitter, List.of(topic("TreeUpdated"), pad(issuer), Hex.encode0x(word(BigInteger.valueOf(LEGACY_TREE_INDEX)))),
                encode(root));
    }

    /** address[] words are left-padded 32-byte words. */
    static List<String> words(List<String> addresses) {
        return addresses.stream().map(Fx::pad).toList();
    }

    record Shape(String name, Log log) {
    }

    static List<Shape> everyShape(String emitter, String issuer, String root) {
        return List.of(
                new Shape("current single", singleLog(emitter, issuer, root)),
                new Shape("current cross-issuer batch",
                        batchLog(emitter, List.of(OTHER, issuer), List.of(leaf(1), root))),
                new Shape("current issuer batch", issuerBatchLog(emitter, issuer, List.of(leaf(2), root))),
                new Shape("legacy single", legacySingleLog(emitter, issuer, root)),
                new Shape("legacy batch", legacyBatchLog(emitter, List.of(OTHER, issuer), List.of(leaf(3), root))));
    }

    static TxReceipt ok(Log... logs) {
        return new TxReceipt(1, Arrays.asList(logs));
    }

    static ReceiptSource stub(TxReceipt receipt) {
        return tx -> receipt;
    }

    static ReceiptSource failing(RuntimeException e) {
        return tx -> {
            throw e;
        };
    }

    /** Registry trusting REGISTRY plus extras, reading from the given receipt source. */
    static CredentialRegistry registry(ReceiptSource src, String... alsoTrust) {
        return new CredentialRegistry(src, null, REGISTRY, alsoTrust);
    }
}
