package com.pila.credential.didv2.subdid;

import com.pila.credential.didv2.Hex;
import com.pila.credential.didv2.KeyPair;
import com.pila.credential.didv2.Secp256k1;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Security;

public final class SubDIDKeys {
    private static final byte[] KDF_SALT = "subdid-keygen-v1".getBytes(StandardCharsets.UTF_8);
    private static final String KDF_INFO_PREFIX = "subdid-key-v1";
    private static final int KDF_LENGTH = 48;

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private SubDIDKeys() {
    }

    public static KeyPair deriveSubDIDKey(String rootPrivateKeyHex, String subID) throws Exception {
        byte[] root = Hex.decode(rootPrivateKeyHex);
        if (root.length != 32) {
            throw new Exception("subdid: root private key must be 32 bytes of hex");
        }
        BigInteger rootScalar = new BigInteger(1, root);
        if (rootScalar.signum() == 0 || rootScalar.compareTo(Secp256k1.N) >= 0) {
            throw new Exception("subdid: root private key is out of range");
        }
        String id = SubDIDDocuments.parseSubID(subID);
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(root, KDF_SALT, (KDF_INFO_PREFIX + id).getBytes(StandardCharsets.UTF_8)));
        byte[] okm = new byte[KDF_LENGTH];
        hkdf.generateBytes(okm, 0, KDF_LENGTH);
        byte[] child = Hex.toFixed(reduceToP256Scalar(okm).toByteArray(), 32);
        byte[] secpPub = Secp256k1.publicFromPrivate(child, true);
        ECParameterSpec p256 = ECNamedCurveTable.getParameterSpec("prime256v1");
        var q = p256.getG().multiply(new BigInteger(1, child)).normalize();
        byte[] p256Uncompressed = q.getEncoded(false);
        KeyPair kp = new KeyPair();
        kp.privateKeyHex = Hex.encode0x(child);
        kp.publicKeyHex = Hex.encode0x(secpPub);
        kp.address = Secp256k1.addressFromPublicKey(secpPub);
        kp.p256X = Hex.encode(java.util.Arrays.copyOfRange(p256Uncompressed, 1, 33));
        kp.p256Y = Hex.encode(java.util.Arrays.copyOfRange(p256Uncompressed, 33, 65));
        return kp;
    }

    private static BigInteger reduceToP256Scalar(byte[] okm) {
        ECParameterSpec p256 = ECNamedCurveTable.getParameterSpec("prime256v1");
        BigInteger nMinusOne = p256.getN().subtract(BigInteger.ONE);
        return new BigInteger(1, okm).mod(nMinusOne).add(BigInteger.ONE);
    }
}
