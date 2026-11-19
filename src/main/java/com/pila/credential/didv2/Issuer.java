package com.pila.credential.didv2;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

public final class Issuer {
    public static final String CAP_CREATE_ACTION = "CAP_CREATE";
    public static final int CAP_ID_LENGTH = 32;
    public static final long DEFAULT_EPOCH = 0;

    private Issuer() {
    }

    public static final class IssueDIDPayload {
        public String contractAddress;
        public String issuerAddress;
        public String didAddress;
        public int didType;
        public String capId;
        public long epoch;
    }

    public static final class IssuerSignature {
        public BigInteger v;
        public BigInteger r;
        public BigInteger s;
    }

    public static void validateIssueDIDPayload(IssueDIDPayload p) throws Exception {
        if (!isAddress(p.contractAddress)) {
            throw new Exception("invalid contract address: " + p.contractAddress);
        }
        if (!isAddress(p.issuerAddress)) {
            throw new Exception("invalid issuer address: " + p.issuerAddress);
        }
        if (!isAddress(p.didAddress)) {
            throw new Exception("invalid did address: " + p.didAddress);
        }
        // +2 for the "0x" prefix: exactly 66 characters, like Go
        if (p.capId == null || p.capId.length() != CAP_ID_LENGTH * 2 + 2) {
            throw new Exception("invalid cap id length: expected " + CAP_ID_LENGTH + ", got "
                    + (p.capId == null ? 0 : p.capId.length()));
        }
    }

    public static byte[] buildIssueDIDPayload(IssueDIDPayload input) throws Exception {
        validateIssueDIDPayload(input);
        if (input.didType < 0 || input.didType > 0xff) {
            throw new Exception("value " + input.didType + " exceeds uint8 max value");
        }
        byte[] capId;
        try {
            capId = Hex.decodeGo(input.capId);
        } catch (IllegalArgumentException e) {
            throw new Exception("invalid bytes32 " + input.capId + ": " + e.getMessage(), e);
        }
        if (capId.length != CAP_ID_LENGTH) {
            throw new Exception("bytes32 must be 32 bytes, got " + capId.length);
        }
        byte[] packed = abiEncodePacked(
                CAP_CREATE_ACTION.getBytes(StandardCharsets.UTF_8),
                addressBytes(input.issuerAddress),
                addressBytes(input.didAddress),
                new byte[] { (byte) input.didType },
                uint64(input.epoch),
                capId);
        byte[] prefix = new byte[] { 0x19, 0x00 };
        byte[] addr = addressBytes(input.contractAddress);
        byte[] out = new byte[prefix.length + addr.length + packed.length];
        System.arraycopy(prefix, 0, out, 0, prefix.length);
        System.arraycopy(addr, 0, out, prefix.length, addr.length);
        System.arraycopy(packed, 0, out, prefix.length + addr.length, packed.length);
        return out;
    }

    public static IssuerSignature generateIssueDIDSignature(IssueDIDPayload input, Signer issuerSigner)
            throws Exception {
        if (issuerSigner == null) {
            throw new Exception("issuer signer is required");
        }
        byte[] payload = buildIssueDIDPayload(input);
        byte[] hash = Keccak256.hash(payload);
        return signatureFromBytes(issuerSigner.sign(hash));
    }

    public static String generateCapID() {
        byte[] b = new byte[CAP_ID_LENGTH];
        new SecureRandom().nextBytes(b);
        return Hex.encode0x(b);
    }

    public static IssuerSignature signatureFromBytes(byte[] sig) throws Exception {
        if (sig.length != 65) {
            throw new Exception("signature must be 65 bytes, got " + sig.length);
        }
        int v = sig[64] & 0xff;
        if (v < 27) {
            v += 27;
        }
        byte[] copy = Arrays.copyOf(sig, 65);
        copy[64] = (byte) v;
        IssuerSignature out = new IssuerSignature();
        out.r = new BigInteger(1, Arrays.copyOfRange(copy, 0, 32));
        out.s = new BigInteger(1, Arrays.copyOfRange(copy, 32, 64));
        out.v = BigInteger.valueOf(v);
        return out;
    }

    public static boolean isAddress(String s) {
        // Go common.IsHexAddress: an optional 0x/0X prefix, then exactly 40 ASCII hex digits
        if (s == null) {
            return false;
        }
        String n = s.length() >= 2 && s.charAt(0) == '0' && (s.charAt(1) == 'x' || s.charAt(1) == 'X')
                ? s.substring(2)
                : s;
        if (n.length() != 40) {
            return false;
        }
        for (int i = 0; i < n.length(); i++) {
            if (Hex.digit(n.charAt(i)) < 0) {
                return false;
            }
        }
        return true;
    }

    static byte[] addressBytes(String s) {
        return Hex.decode(s);
    }

    /**
     * Go encodes the epoch through {@code strconv.Itoa(int(Epoch))} and {@code big.Int.Bytes()}, which is the
     * magnitude of the signed 64-bit value: a uint64 epoch of 2^63 or more is written as its two's-complement
     * magnitude, not as the unsigned value.
     */
    private static byte[] uint64(long v) {
        if (v < 0) {
            v = -v;
        }
        byte[] out = new byte[8];
        for (int i = 7; i >= 0; i--) {
            out[i] = (byte) (v & 0xff);
            v >>= 8;
        }
        return out;
    }

    private static byte[] abiEncodePacked(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int o = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, o, p.length);
            o += p.length;
        }
        return out;
    }
}
