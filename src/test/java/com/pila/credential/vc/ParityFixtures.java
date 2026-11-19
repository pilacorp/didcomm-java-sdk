package com.pila.credential.vc;

import com.pila.credential.common.verificationmethod.DIDDocument;
import com.pila.credential.common.verificationmethod.JWK;
import com.pila.credential.common.verificationmethod.StaticDocumentResolver;
import com.pila.credential.common.verificationmethod.VerificationMethodEntry;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/** Offline keys, DID documents and contents shared by the Go-parity tests. */
public final class ParityFixtures {
    public static final String SECP_PRIV = "2c79686425aee8002cb189bf294f2d52ca43851797c7b6e78a7dc361c4373e46";
    public static final String P256_PRIV = "1111111111111111111111111111111111111111111111111111111111111112";

    private ParityFixtures() {
    }

    public static DIDDocument secpDoc(String did) {
        BigInteger d = new BigInteger(1, Hex.decode(SECP_PRIV));
        ECPoint q = ECNamedCurveTable.getParameterSpec("secp256k1").getG().multiply(d).normalize();
        VerificationMethodEntry vm = new VerificationMethodEntry();
        vm.setId(did + "#key-1");
        vm.setType("EcdsaSecp256k1VerificationKey2019");
        vm.setController(did);
        vm.setPublicKeyHex(Hex.toHexString(q.getEncoded(false)));
        return doc(did, vm);
    }

    public static DIDDocument p256Doc(String did) {
        BigInteger d = new BigInteger(1, Hex.decode(P256_PRIV));
        ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("prime256v1");
        ECPoint q = spec.getG().multiply(d).normalize();
        JWK jwk = new JWK();
        jwk.setKty("EC");
        jwk.setCrv("P-256");
        jwk.setX(b64(fixed32(q.getAffineXCoord().toBigInteger())));
        jwk.setY(b64(fixed32(q.getAffineYCoord().toBigInteger())));
        VerificationMethodEntry vm = new VerificationMethodEntry();
        vm.setId(did + "#key-1");
        vm.setType("JsonWebKey2020");
        vm.setController(did);
        vm.setPublicKeyJwk(jwk);
        return doc(did, vm);
    }

    private static DIDDocument doc(String did, VerificationMethodEntry vm) {
        DIDDocument doc = new DIDDocument();
        doc.setId(did);
        doc.setVerificationMethod(List.of(vm));
        doc.setAssertionMethod(List.of(vm.getId()));
        doc.setAuthentication(List.of(vm.getId()));
        return doc;
    }

    public static StaticDocumentResolver resolver(DIDDocument... docs) {
        return new StaticDocumentResolver(docs);
    }

    /** VC 2.0 contents with the required properties. */
    public static CredentialContents contents(String issuer) {
        CredentialContents c = new CredentialContents();
        c.setContext(List.of("https://www.w3.org/ns/credentials/v2"));
        c.setTypes(List.of("VerifiableCredential"));
        c.setIssuer(issuer);
        c.setValidFrom(Instant.now().minusSeconds(60));
        c.setSubject(List.of(new Subject("did:example:subject", new java.util.HashMap<>(Map.of("name", "Alice")))));
        return c;
    }

    public static CredentialContents contentsV1(String issuer) {
        CredentialContents c = contents(issuer);
        c.setContext(List.of("https://www.w3.org/2018/credentials/v1"));
        return c;
    }

    private static byte[] fixed32(BigInteger v) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[32];
        if (raw.length > 32) {
            System.arraycopy(raw, raw.length - 32, out, 0, 32);
        } else {
            System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
        }
        return out;
    }

    private static String b64(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }
}
