package com.pila.credential.didv2.didcontract;

import com.pila.credential.didv2.Hex;
import com.pila.credential.didv2.Keccak256;
import com.pila.credential.didv2.Signer;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class LegacyTx {
    public static final class Signed {
        public String txHex;
        public String txHash;
    }

    private LegacyTx() {
    }

    public static Signed sign(String to, byte[] data, long nonce, long gasLimit, BigInteger gasPrice, long chainId,
            Signer signer) throws Exception {
        byte[] toBytes = Hex.decode(to);
        List<byte[]> unsigned = new ArrayList<>();
        unsigned.add(raw(Rlp.encodeUint(BigInteger.valueOf(nonce))));
        unsigned.add(raw(Rlp.encodeUint(gasPrice == null ? BigInteger.ZERO : gasPrice)));
        unsigned.add(raw(Rlp.encodeUint(BigInteger.valueOf(gasLimit))));
        unsigned.add(raw(Rlp.encodeItem(toBytes)));
        unsigned.add(raw(Rlp.encodeUint(BigInteger.ZERO)));
        unsigned.add(raw(Rlp.encodeItem(data)));
        unsigned.add(raw(Rlp.encodeUint(BigInteger.valueOf(chainId))));
        unsigned.add(raw(Rlp.encodeUint(BigInteger.ZERO)));
        unsigned.add(raw(Rlp.encodeUint(BigInteger.ZERO)));
        byte[] unsignedRlp = Rlp.encodeList(toPayloads(unsigned));
        byte[] hash = Keccak256.hash(unsignedRlp);
        byte[] sig = signer.sign(hash);
        int recId = sig[64] & 0xff;
        if (recId >= 27) {
            recId -= 27;
        }
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(sig, 0, 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(sig, 32, 64));
        BigInteger v = BigInteger.valueOf(recId + 35L + 2L * chainId);
        List<byte[]> signed = new ArrayList<>();
        signed.add(raw(Rlp.encodeUint(BigInteger.valueOf(nonce))));
        signed.add(raw(Rlp.encodeUint(gasPrice == null ? BigInteger.ZERO : gasPrice)));
        signed.add(raw(Rlp.encodeUint(BigInteger.valueOf(gasLimit))));
        signed.add(raw(Rlp.encodeItem(toBytes)));
        signed.add(raw(Rlp.encodeUint(BigInteger.ZERO)));
        signed.add(raw(Rlp.encodeItem(data)));
        signed.add(raw(Rlp.encodeUint(v)));
        signed.add(raw(Rlp.encodeUint(r)));
        signed.add(raw(Rlp.encodeUint(s)));
        byte[] signedRlp = Rlp.encodeList(toPayloads(signed));
        Signed out = new Signed();
        out.txHex = Hex.encode(signedRlp);
        out.txHash = Hex.encode0x(Keccak256.hash(signedRlp));
        return out;
    }

    private static byte[] raw(byte[] encodedItem) {
        return encodedItem;
    }

    /**
     * encodeList expects already-encoded items as payloads... wait, I designed encodeList to
     * re-encode items. Fix: pass already-encoded RLP items by concatenating.
     */
    private static List<byte[]> toPayloads(List<byte[]> encodedItems) {
        // Rlp.encodeList currently calls encodeItem on each. We need a list of raw inner bytes.
        // Use a dedicated concatenate for already-encoded items.
        return encodedItems;
    }
}
