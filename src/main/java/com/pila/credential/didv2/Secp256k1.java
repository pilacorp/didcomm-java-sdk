package com.pila.credential.didv2;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Arrays;

public final class Secp256k1 {
    private static final X9ECParameters CURVE_PARAMS = SECNamedCurves.getByName("secp256k1");
    static final ECDomainParameters CURVE = new ECDomainParameters(
            CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(), CURVE_PARAMS.getH());
    public static final BigInteger N = CURVE.getN();
    public static final BigInteger HALF_N = N.shiftRight(1);

    private Secp256k1() {
    }

    public static byte[] compress(byte[] pub) {
        ECPoint p = CURVE.getCurve().decodePoint(pub);
        return p.getEncoded(true);
    }

    public static byte[] decompress(byte[] compressed) {
        return CURVE.getCurve().decodePoint(compressed).getEncoded(false);
    }

    public static byte[] publicFromPrivate(byte[] priv32, boolean compressed) {
        BigInteger d = new BigInteger(1, priv32);
        ECPoint q = CURVE.getG().multiply(d).normalize();
        return q.getEncoded(compressed);
    }

    public static String addressFromPublicKey(byte[] pub) {
        // decodePoint rejects an off-curve uncompressed key too (Go crypto.UnmarshalPubkey)
        byte[] uncompressed = decompress(pub);
        byte[] hash = Keccak256.hash(Arrays.copyOfRange(uncompressed, 1, uncompressed.length));
        return Hex.encode0x(Arrays.copyOfRange(hash, 12, 32)).toLowerCase();
    }

    public static String addressFromPrivate(byte[] priv32) {
        return addressFromPublicKey(publicFromPrivate(priv32, false));
    }

    /**
     * Signs a 32-byte digest. Returns 65 bytes R||S||V with V in {0,1} (go-ethereum crypto.Sign).
     */
    public static byte[] sign(byte[] digest32, byte[] priv32) throws Exception {
        if (digest32.length != 32) {
            throw new Exception("failed to sign payload: digest must be 32 bytes");
        }
        BigInteger d = new BigInteger(1, priv32);
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(true, new ECPrivateKeyParameters(d, CURVE));
        BigInteger[] rs = signer.generateSignature(digest32);
        BigInteger r = rs[0];
        BigInteger s = rs[1];
        if (s.compareTo(HALF_N) > 0) {
            s = N.subtract(s);
        }
        ECPoint pub = CURVE.getG().multiply(d).normalize();
        int recId = -1;
        for (int i = 0; i < 4; i++) {
            ECPoint q = recover(i, r, s, digest32);
            if (q != null && q.equals(pub)) {
                recId = i;
                break;
            }
        }
        if (recId < 0) {
            throw new Exception("failed to compute recovery id");
        }
        byte[] sig = new byte[65];
        System.arraycopy(Hex.toFixed(r.toByteArray(), 32), 0, sig, 0, 32);
        System.arraycopy(Hex.toFixed(s.toByteArray(), 32), 0, sig, 32, 32);
        sig[64] = (byte) recId;
        return sig;
    }

    public static byte[] recoverPublic(byte[] digest32, byte[] sig65) throws Exception {
        byte[] sig = Arrays.copyOf(sig65, 65);
        int v = sig[64] & 0xff;
        if (v >= 27) {
            v -= 27;
        }
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(sig, 0, 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(sig, 32, 64));
        ECPoint q = recover(v, r, s, digest32);
        if (q == null) {
            throw new Exception("recover signer: failed");
        }
        return q.getEncoded(false);
    }

    private static ECPoint recover(int recId, BigInteger r, BigInteger s, byte[] message) {
        BigInteger n = N;
        BigInteger i = BigInteger.valueOf(recId / 2);
        BigInteger x = r.add(i.multiply(n));
        if (x.compareTo(CURVE.getCurve().getField().getCharacteristic()) >= 0) {
            return null;
        }
        ECPoint R;
        try {
            R = decompressKey(x, (recId & 1) == 1);
        } catch (Exception e) {
            return null;
        }
        if (!R.multiply(n).isInfinity()) {
            return null;
        }
        BigInteger e = new BigInteger(1, message);
        BigInteger rInv = r.modInverse(n);
        BigInteger srInv = rInv.multiply(s).mod(n);
        BigInteger eNeg = rInv.multiply(n.subtract(e)).mod(n);
        return ECAlgorithms.sumOfTwoMultiplies(CURVE.getG(), eNeg, R, srInv).normalize();
    }

    private static ECPoint decompressKey(BigInteger xBN, boolean yBit) {
        byte[] enc = Hex.toFixed(xBN.toByteArray(), 33);
        enc[0] = (byte) (yBit ? 0x03 : 0x02);
        return CURVE.getCurve().decodePoint(enc);
    }
}
