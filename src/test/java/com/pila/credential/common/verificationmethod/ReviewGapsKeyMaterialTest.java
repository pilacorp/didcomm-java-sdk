package com.pila.credential.common.verificationmethod;

import com.pila.credential.common.signer.AlgorithmProvider;
import com.pila.credential.common.signer.LowS;
import com.pila.credential.common.signer.P256SignerProvider;
import com.pila.credential.common.signer.RSASignerProvider;
import com.pila.credential.common.signer.SignerProvider;
import com.pila.credential.common.util.Multibase;
import com.pila.credential.didv2.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Review rows 3.35-3.37, 4.28, 5.14-5.25, 6.8, 6.10, 6.18. Expected values come from a Go program run against
 * go-credential-sdk main (credential/common/verification-method and signer).
 */
public class ReviewGapsKeyMaterialTest {
    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static final String SEC = "0x03354b9ae48c3cecaf6636ba88e321847edbf450a2777a012240d6d51705de73d7";
    private static final String MB256 = "zDnaeimWMwMjMbqrvY6z4PqLZ6Fzgu1HukAbCTCScAZucR7hY";
    private static final String MB384 =
            "z82Lkpc5WxSdJa9AEJ5XNxJFJuJfg13D1yJAWbxtdKL2uPH28V9D3KGFZkcxScQ1FbgxKax";
    private static final String P256_X = "EHPPCRDveJ8J1uKro8F_pRRls7ZXMN1zPcsfmgkL2Pc";
    private static final String P256_Y = "IjLKKGBv2ocqzD3IM6uRDPlJVmVLrFyMMd1fP_iAmak";
    private static final String P384_X = "b19VLHU9lrzWhyAJNeNblPW4qUvCrgkiZ1KDZ77bGvKoIIp1qSSRENZEGGokkxgB";
    private static final String P384_Y = "vGL7DuBMVa6i8WgKEDpS6uPTSpmn2m0ykSl0s_6DnfBe6lBKgWUEImywQfqpR54c";

    private static JWK jwk(String kty, String crv, String x, String y) {
        JWK j = new JWK();
        j.setKty(kty);
        j.setCrv(crv);
        j.setX(x);
        j.setY(y);
        return j;
    }

    // ---- 5.16 base58, 5.14/5.15 multikey, 5.17 private multikey ----

    @Test
    void base58RejectsEmptyAndKeepsAllOnesAsZeroBytes() throws Exception {
        assertThrows(Exception.class, () -> Multikey.decodeMultibaseKey("z"));
        assertThrows(Exception.class, () -> Multikey.decodeMultibaseKey(""));
        assertThrows(Exception.class, () -> Multikey.decodeMultibaseKey("zO"));
        assertThrows(Exception.class, () -> Multikey.decodeMultibaseKey("y123"));
        assertArrayEquals(new byte[3], Multikey.decodeMultibaseKey("z111"));
        assertArrayEquals(new byte[1], Multikey.decodeMultibaseKey("z1"));
    }

    @Test
    void multikeyDecodeFollowsGoCurvesAndShape() throws Exception {
        assertEquals(Multikey.Curve.P256, Multikey.decodeEc(MB256).curve());
        assertEquals(Multikey.Curve.P384, Multikey.decodeEc(MB384).curve());
        // uncompressed 04, hybrid 06/07, trailing byte, prefix only, one byte, unknown prefix, short P-384
        for (String bad : List.of(
                "z4oJ8a7FFNRvtMZZCst4JPsFTwfsHbiYXEcYcHENazyMMBq6cjDPek5h2kZz98V35S6AmueKv3jzHtShdWvbR53ssnCrU",
                "z4oJ8qTpjBRYbenBzMG175SE5QsDBwtJyJ1odgCNcokNLQrYA8Dpgrh1MRfBV8X32iE2BN6fRJogpN4hBuxmLk63QBnFi",
                "zySBXVMSbQvVwvnfMJHQqynMJeDBd6YHdoXKwYdW2DEFDKSZuq", "zAkb", "z3D",
                "zQ3shfkL59UPAC1YMA3LpuQ7EFXwtVxMkGM7bSGtxu5zpFpWA",
                "z2bHiCEqbt5Su1iGgiUm3Fo3nk7iqiF6SbWGJ8UARzd2nrTHZxmTHqYYr7FwhhC6wxteTR")) {
            assertThrows(Exception.class, () -> Multikey.decodeEc(bad), bad);
        }
        // x = 0 is a point on P-256 (Go accepts it)
        assertEquals(Multikey.Curve.P256,
                Multikey.decodeEc("zDnaeQRy3dcKsKa1zmKtVKsTy3m2HYoQnFnfKuxD6HfSTQgYf").curve());
        // the two-byte minimum: 2 bytes is "too short" only below 2
        assertThrows(Exception.class, () -> Multikey.decodeEcBytes(new byte[] { (byte) 0x80 }));
    }

    @Test
    void multikeyEncodeChecksCurveAndEncodesP384() throws Exception {
        PublicKey p256 = ReviewGapsKeyMaterialTest.<PublicKey>ecKey("P-256", P256_X, P256_Y);
        PublicKey p384 = ecKey("P-384", P384_X, P384_Y);
        assertEquals(MB256, Multikey.encodePublicKey(p256));
        assertEquals(MB384, Multikey.encodePublicKey(p384));
        assertEquals(MB256, Multikey.encodeP256PublicKey(p256));
        assertThrows(Exception.class, () -> Multikey.encodeP256PublicKey(p384));
        PublicKey k1 = VerificationMethodMaterial.secp256k1PubFromHex(SEC);
        assertThrows(Exception.class, () -> Multikey.encodePublicKey(k1));
    }

    @Test
    void privateMultikeyMustBeExactly32BytesInRange() throws Exception {
        assertEquals(BigInteger.valueOf(5),
                Multikey.decodeP256PrivMultibase("z42thtK4xkebhpMHF4yzF9ZJqAa4rvBxg3Pt41EVVKwKzRnk"));
        for (String bad : List.of("zEPMDTUkV5exB9zWh6aXfSmbhbEx3KmNjKZzLG2Yk2anpUQtp", // trailing byte
                "z42thtK4xkebhpMHF4yzF9ZJqAa4rvBxg3Pt41EVVKwKzRnf", // d = 0
                "z42u17dSTVmUzkGfRt5tahAKxsvnmXSJHm4TNLvKXfoGtTC4", // d = n
                "z2sQ2PquXHLSMoVrRmgDkVJSqm8Uf")) { // short
            assertThrows(Exception.class, () -> Multikey.decodeP256PrivMultibase(bad), bad);
        }
    }

    // ---- 5.19 JWK / 4.28 key source order / 5.18 / 5.21 ----

    @Test
    void jwkParsingIsRawUrlOnCurveAndSizeLimited() throws Exception {
        assertNotNull(VerificationMethodMaterial.ecPubFromJwk(jwk("EC", "P-256", P256_X, P256_Y)));
        PublicKey p384 = VerificationMethodMaterial.ecPubFromJwk(jwk("EC", "P-384", P384_X, P384_Y));
        assertEquals(MB384, Multikey.encodePublicKey(p384));
        assertThrows(Exception.class, () -> VerificationMethodMaterial.ecPubFromJwk(
                jwk("EC", "P-256", P256_X + "=", P256_Y))); // padding
        assertThrows(Exception.class, () -> VerificationMethodMaterial.ecPubFromJwk(
                jwk("EC", "P-256", P256_X, P256_X))); // off curve
        assertThrows(Exception.class, () -> VerificationMethodMaterial.ecPubFromJwk(
                jwk("EC", "P-256", "ABBzzwkQ73ifCdbiq6PBf6UUZbO2VzDdcz3LH5oJC9j3", P256_Y))); // 33 bytes
        assertThrows(Exception.class, () -> VerificationMethodMaterial.ecPubFromJwk(jwk("EC", "P-521", "AQ", "AQ")));
        assertThrows(Exception.class, () -> VerificationMethodMaterial.ecPubFromJwk(jwk("OKP", "Ed25519", "AQ", null)));
        // a short coordinate is left-padded (Go: some DID documents strip leading zeros)
        PublicKey padded = VerificationMethodMaterial.ecPubFromJwk(jwk("EC", "P-256",
                "aQd_Ht9U9UdifuaxGoeXq5J5-7ee2GM2YNHDnZMPbQ", "t92rmJSEDqUNRwB_x94laU4-XFPqc5MVCoZPNcyRjSE"));
        assertEquals(new BigInteger("69077f1edf54f547627ee6b11a8797ab9279fbb79ed8633660d1c39d930f6d", 16),
                ((ECPublicKey) padded).getW().getAffineX());
        assertThrows(Exception.class, () -> VerificationMethodMaterial.p256PubKeyFromJwk(
                jwk("EC", "P-384", P384_X, P384_Y)));
    }

    @Test
    void rsaJwkRoundTripsThroughVmBuilder() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        var kp = g.generateKeyPair();
        VerificationMethodEntry vm = VerificationMethods.newRSAVM("did:x:1", "key-1", (RSAPublicKey) kp.getPublic());
        assertEquals("did:x:1#key-1", vm.getId());
        assertEquals("JsonWebKey2020", vm.getType());
        assertEquals("AQAB", vm.getPublicKeyJwk().getE());
        RSAPublicKey back = VerificationMethodMaterial.rsaPubKeyFromJwk(vm.getPublicKeyJwk());
        assertEquals(((RSAPublicKey) kp.getPublic()).getModulus(), back.getModulus());
        assertEquals(VerificationMethodKeyKind.RSA, VerificationMethodKeyKind.fromEntry(vm));
        JWK noE = new JWK();
        noE.setKty("RSA");
        noE.setN("AQAB");
        assertThrows(Exception.class, () -> VerificationMethodMaterial.rsaPubKeyFromJwk(noE));
    }

    @Test
    void ecPubFromVmTakesHexFirstWithoutTypeGating() throws Exception {
        VerificationMethodEntry vm = new VerificationMethodEntry();
        vm.setId("a");
        vm.setType("Multikey"); // no type gating
        vm.setPublicKeyHex(SEC);
        vm.setPublicKeyMultibase(MB256);
        vm.setPublicKeyJwk(jwk("EC", "P-256", P256_X, P256_Y));
        ECPublicKey hexFirst = (ECPublicKey) VerificationMethodMaterial.ecPublicKeyFromEntry(vm);
        assertEquals(256, hexFirst.getParams().getOrder().bitLength());
        // kind: a JWK is consulted before publicKeyHex (Go VMIsSecp256k1), so this VM reads as P-256
        assertEquals(VerificationMethodKeyKind.P256, VerificationMethodKeyKind.fromEntry(vm));
        vm.setPublicKeyHex(null);
        vm.setPublicKeyMultibase(MB256);
        vm.setPublicKeyJwk(jwk("EC", "P-384", P384_X, P384_Y)); // JWK before multibase
        assertEquals(384, ((ECPublicKey) VerificationMethodMaterial.ecPublicKeyFromEntry(vm)).getParams()
                .getOrder().bitLength());
    }

    @Test
    void secp256k1HexIsStrictAscii() throws Exception {
        assertNotNull(VerificationMethodMaterial.secp256k1PubFromHex("0X" + SEC.substring(2)));
        assertNotNull(VerificationMethodMaterial.secp256k1PubFromHex(SEC.substring(2)));
        assertThrows(Exception.class, () -> VerificationMethodMaterial.secp256k1PubFromHex(SEC + "zz"));
        assertThrows(Exception.class, () -> VerificationMethodMaterial.secp256k1PubFromHex("0x0400"));
        assertThrows(Exception.class, () -> VerificationMethodMaterial.secp256k1PubFromHex("０３"));
    }

    @Test
    void keyKindMatchesGoVMKeyKind() throws Exception {
        VerificationMethodEntry hexMultikeyType = new VerificationMethodEntry();
        hexMultikeyType.setType("Multikey");
        hexMultikeyType.setPublicKeyHex(SEC);
        assertEquals(VerificationMethodKeyKind.SECP256K1, VerificationMethodKeyKind.fromEntry(hexMultikeyType));
        VerificationMethodEntry p256jwk = new VerificationMethodEntry();
        p256jwk.setPublicKeyJwk(jwk("EC", "P-256", P256_X, P256_Y));
        assertEquals(VerificationMethodKeyKind.P256, VerificationMethodKeyKind.fromEntry(p256jwk));
        VerificationMethodEntry p256mb = new VerificationMethodEntry();
        p256mb.setPublicKeyMultibase(MB256);
        assertEquals(VerificationMethodKeyKind.P256, VerificationMethodKeyKind.fromEntry(p256mb));
        assertTrue(VerificationMethodKeyKind.vmIsP256(p256mb));
        VerificationMethodEntry p384mb = new VerificationMethodEntry();
        p384mb.setPublicKeyMultibase(MB384);
        assertEquals(VerificationMethodKeyKind.UNKNOWN, VerificationMethodKeyKind.fromEntry(p384mb));
        VerificationMethodEntry emptyJwk = new VerificationMethodEntry();
        emptyJwk.setPublicKeyJwk(new JWK());
        assertEquals(VerificationMethodKeyKind.UNKNOWN, VerificationMethodKeyKind.fromEntry(emptyJwk));
        assertEquals(VerificationMethodKeyKind.UNKNOWN, VerificationMethodKeyKind.fromEntry(new VerificationMethodEntry()));
        assertEquals(VerificationMethodKeyKind.UNKNOWN, VerificationMethodKeyKind.fromEntry(null));
        assertFalse(VerificationMethodKeyKind.vmIsRSA(null));
        assertEquals("P-256", VerificationMethodKeyKind.P256.label());
    }

    // ---- 3.36/3.37/5.22-5.25 selectors ----

    private static DIDDocument doc(String... fragments) {
        String did = "did:x:1";
        DIDDocument d = new DIDDocument();
        d.setId(did);
        List<VerificationMethodEntry> vms = new ArrayList<>();
        List<String> refs = new ArrayList<>();
        for (String f : fragments) {
            VerificationMethodEntry vm = new VerificationMethodEntry();
            vm.setId(did + f);
            vm.setPublicKeyHex(SEC);
            vms.add(vm);
            refs.add(did + f);
        }
        d.setVerificationMethod(vms);
        d.setAuthentication(new ArrayList<>(refs));
        d.setAssertionMethod(new ArrayList<>(refs));
        return d;
    }

    private static String pick(String... fragments) throws Exception {
        return Selector.selectLatestActiveVMForPurpose(doc(fragments), "authentication").getId().substring(7);
    }

    @Test
    void latestActiveVmTiesGoToTheLargerIdAndFragmentsParseLikeSscanf() throws Exception {
        // expected values: Go SelectLatestActiveVMForPurpose
        assertEquals("#key-1", pick("#key-1", "#key-01"));
        assertEquals("#key-1", pick("#key-01", "#key-1"));
        assertEquals("#key-3x", pick("#key-2", "#key-3x"));
        assertEquals("#key-3x", pick("#key-3x", "#key-2"));
        assertEquals("#key-b", pick("#key-b", "#key-a"));
        assertEquals("#key-b", pick("#key-a", "#key-b"));
        assertEquals("#key-+5", pick("#key-+5", "#key-4"));
        assertEquals("#key-0", pick("#key--3", "#key-0"));
        assertEquals("#key- 7", pick("#key- 7", "#key-6"));
        assertEquals("#key-1", pick("#key-99999999999999999999", "#key-1"));
        assertEquals("#key-9", pick("#key-1_0", "#key-9"));
        assertEquals("#key-x", pick("#key-", "#key-x"));
        assertEquals("#y", pick("#x", "#y"));
    }

    @Test
    void selectByKeyKindAndVmForPurpose() throws Exception {
        DIDDocument d = doc("#key-1", "#key-2");
        VerificationMethodEntry p256 = new VerificationMethodEntry();
        p256.setId("did:x:1#key-3");
        p256.setPublicKeyMultibase(MB256);
        d.getVerificationMethod().add(p256);
        d.getAuthentication().add("#key-3"); // fragment form is accepted too
        assertEquals("did:x:1#key-3",
                Selector.selectLatestActiveVMForKey(d, "authentication", VerificationMethodKeyKind.P256).getId());
        assertEquals("did:x:1#key-2",
                Selector.selectLatestActiveVMForKey(d, "authentication", VerificationMethodKeyKind.SECP256K1).getId());
        Exception e = assertThrows(Exception.class,
                () -> Selector.selectLatestActiveVMForKey(d, "authentication", VerificationMethodKeyKind.RSA));
        assertEquals("no active RSA verification method for purpose 'authentication' on DID 'did:x:1'",
                e.getMessage());
        d.getVerificationMethod().get(1).setRevoked("2026-01-01T00:00:00Z");
        assertEquals("did:x:1#key-1",
                Selector.selectLatestActiveVMForKey(d, "authentication", VerificationMethodKeyKind.SECP256K1).getId());
        // SelectVMForPurpose: a kid (bare, fragment or URL) finds even a revoked VM; empty falls back
        assertEquals("did:x:1#key-2", Selector.selectVMForPurpose(d, "authentication", "key-2").getId());
        assertEquals("did:x:1#key-2", Selector.selectVMForPurpose(d, "authentication", "#key-2").getId());
        assertEquals("did:x:1#key-2", Selector.selectVMForPurpose(d, "authentication", "did:x:1#key-2").getId());
        assertEquals("did:x:1#key-3", Selector.selectVMForPurpose(d, "authentication", "").getId());
        assertThrows(Exception.class, () -> Selector.selectVMForPurpose(d, "authentication", "nope"));
        assertEquals("did:x:1#key-1",
                ResolveVmUrl.resolveVerificationMethodURLForKey("did:x:1", "authentication",
                        VerificationMethodKeyKind.SECP256K1, did -> d));
    }

    @Test
    void didFromVerificationMethodUrlRequiresDidPrefixAndHash() {
        assertEquals("did:nda:0xabc", assertDid("did:nda:0xabc#key-1"));
        for (String bad : List.of("", "did:nda:0xabc", "#key-1", "notdid#key-1")) {
            assertThrows(Exception.class, () -> VerificationMethodMaterial.didFromVerificationMethodURL(bad), bad);
        }
    }

    private static String assertDid(String url) {
        try {
            return VerificationMethodMaterial.didFromVerificationMethodURL(url);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    @Test
    void staticResolverAndDocumentBuilders() throws Exception {
        VerificationMethodEntry vm = VerificationMethods.newSecp256k1VM("did:x:2", "key-1", SEC);
        DIDDocument d = VerificationMethods.newDIDDocument("did:x:2", vm);
        assertEquals(List.of("did:x:2#key-1"), d.getAuthentication());
        assertEquals(List.of("did:x:2#key-1"), d.getAssertionMethod());
        StaticDocumentResolver r = new StaticDocumentResolver(d);
        assertSame(d, r.resolveDocument("did:x:2"));
        assertThrows(Exception.class, () -> r.resolveDocument("did:x:3"));
        ECPublicKey p256 = (ECPublicKey) ecKey("P-256", P256_X, P256_Y);
        VerificationMethodEntry mk = VerificationMethods.newP256MultikeyVM("did:x:2", "key-2", p256);
        assertEquals(MB256, mk.getPublicKeyMultibase());
        assertEquals("Multikey", mk.getType());
        VerificationMethodEntry jw = VerificationMethods.newP256VM("did:x:2", "key-3", p256);
        assertEquals(P256_X, jw.getPublicKeyJwk().getX());
        assertEquals(P256_Y, jw.getPublicKeyJwk().getY());
        assertThrows(Exception.class,
                () -> VerificationMethods.newP256VM("did:x:2", "k", (ECPublicKey) ecKey("P-384", P384_X, P384_Y)));
    }

    private static void assertSame(Object a, Object b) {
        assertTrue(a == b);
    }

    @Test
    void resolveSigningVmHonoursOnlyRevoked() throws Exception {
        DIDDocument d = doc("#key-1", "#key-2");
        d.getVerificationMethod().get(1).setRevocationReason("keyCompromise"); // hard reason, no `revoked`
        assertEquals("did:x:1#key-2", ResolveVmUrl.resolveSigningVM("did:x:1", "authentication", "", did -> d).url());
    }

    // ---- 6.8 signers ----

    @Test
    void p256ProviderLowSFunctionBackedAndAlgorithm() throws Exception {
        P256SignerProvider local = new P256SignerProvider(
                "0x0000000000000000000000000000000000000000000000000000000000000005");
        assertEquals("ES256", local.algorithm());
        assertEquals("ES256", AlgorithmProvider.algorithmOf(local));
        assertNotNull(local.getPublic());
        BigInteger halfN = new BigInteger("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8", 16);
        byte[] digest = new byte[32];
        for (int i = 0; i < 40; i++) {
            digest[31] = (byte) i;
            byte[] sig = local.sign(digest);
            assertEquals(64, sig.length);
            assertTrue(new BigInteger(1, Arrays.copyOfRange(sig, 32, 64)).compareTo(halfN) <= 0);
        }
        assertThrows(IllegalArgumentException.class, () -> local.sign(new byte[31]));
        // function-backed (HSM/KMS): same class, digest is forwarded, 32-byte guard still applies
        byte[][] seen = new byte[1][];
        P256SignerProvider fn = P256SignerProvider.fromFunc(d -> {
            seen[0] = d;
            return new byte[64];
        });
        assertNull(fn.getPublic());
        assertEquals(64, fn.sign(digest).length);
        assertArrayEquals(digest, seen[0]);
        assertThrows(IllegalArgumentException.class, () -> fn.sign(new byte[5]));
        assertThrows(IllegalArgumentException.class, () -> P256SignerProvider.fromFunc(null));
        // in-memory key overload
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");
        g.initialize(new java.security.spec.ECGenParameterSpec("prime256v1"));
        var kp = g.generateKeyPair();
        P256SignerProvider fromKey = new P256SignerProvider(kp.getPrivate());
        byte[] sig = fromKey.sign(digest);
        Signature v = Signature.getInstance("NONEwithECDSA", "BC");
        v.initVerify(fromKey.getPublic());
        v.update(digest);
        assertTrue(v.verify(toDer(sig)));
        java.security.PrivateKey k1 = secp256k1Private();
        assertThrows(IllegalArgumentException.class, () -> new P256SignerProvider(k1));
    }

    private static java.security.PrivateKey secp256k1Private() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");
        g.initialize(new java.security.spec.ECGenParameterSpec("secp256k1"));
        return g.generateKeyPair().getPrivate();
    }

    private static byte[] toDer(byte[] raw64) throws Exception {
        return new org.bouncycastle.asn1.DERSequence(new org.bouncycastle.asn1.ASN1Encodable[] {
                new org.bouncycastle.asn1.ASN1Integer(new BigInteger(1, Arrays.copyOfRange(raw64, 0, 32))),
                new org.bouncycastle.asn1.ASN1Integer(new BigInteger(1, Arrays.copyOfRange(raw64, 32, 64))) })
                .getEncoded();
    }

    @Test
    void lowSNormalizeMatchesGo() {
        BigInteger n = new BigInteger("ffffffffffffffffffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16);
        assertEquals(BigInteger.TEN, LowS.normalize(n, BigInteger.TEN));
        assertEquals(BigInteger.ONE, LowS.normalize(n, n.subtract(BigInteger.ONE)));
    }

    @Test
    void rsaProviderSignsPkcs1AndPssOverDigests() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        var kp = g.generateKeyPair();
        byte[] msg = "signing input".getBytes();
        assertEquals("RS256", AlgorithmProvider.algorithmOf(new RSASignerProvider(kp.getPrivate())));
        assertEquals("RS256", AlgorithmProvider.algorithmOf((SignerProvider) d -> d));
        for (String alg : List.of("RS256", "RS384", "RS512", "PS256", "PS384", "PS512")) {
            String hash = RSASignerProvider.hashName(alg);
            byte[] digest = MessageDigest.getInstance(hash).digest(msg);
            RSASignerProvider p = new RSASignerProvider(kp.getPrivate(), alg);
            assertEquals(alg, p.algorithm());
            byte[] sig = p.sign(digest);
            assertEquals(256, sig.length);
            Signature v;
            if (alg.startsWith("RS")) {
                v = Signature.getInstance(hash.replace("-", "") + "withRSA");
            } else {
                v = Signature.getInstance("RSASSA-PSS");
                int saltLen = 256 - digest.length - 2; // Go PSSSaltLengthAuto when signing
                v.setParameter(new PSSParameterSpec(hash, "MGF1", new MGF1ParameterSpec(hash), saltLen, 1));
            }
            v.initVerify(kp.getPublic());
            v.update(msg);
            assertTrue(v.verify(sig), alg);
        }
        RSASignerProvider fn = RSASignerProvider.fromFunc(d -> d, "PS384");
        assertEquals("PS384", fn.algorithm());
        assertThrows(IllegalArgumentException.class, () -> new RSASignerProvider(kp.getPrivate(), "ES256"));
        assertThrows(IllegalArgumentException.class, () -> RSASignerProvider.fromFunc(null, "RS256"));
    }

    // ---- helpers ----

    @SuppressWarnings("unchecked")
    private static <T extends PublicKey> T ecKey(String crv, String x, String y) throws Exception {
        return (T) VerificationMethodMaterial.ecPubFromJwk(jwk("EC", crv, x, y));
    }

    @Test
    void multibaseEncodeDecodeRoundTripsLeadingZeros() {
        byte[] raw = { 0, 0, 1, 2, 3 };
        assertArrayEquals(raw, Multibase.decodeBase58Btc(Multibase.encodeBase58Btc(raw)));
        assertEquals("0102", Hex.encode(new byte[] { 1, 2 }));
    }
}
