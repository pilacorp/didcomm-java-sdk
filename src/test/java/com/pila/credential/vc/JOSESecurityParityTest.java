package com.pila.credential.vc;

import com.pila.credential.common.jwt.JWTSigner;
import com.pila.credential.common.signer.DefaultSignerProvider;
import com.pila.credential.common.signer.P256SignerProvider;
import com.pila.credential.common.verificationmethod.DIDDocument;
import com.pila.credential.common.verificationmethod.JWK;
import com.pila.credential.common.verificationmethod.StaticDocumentResolver;
import com.pila.credential.common.verificationmethod.VerificationMethodEntry;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Blocking security/interop findings from the PR #10 parity review:
 *  - A1: JWT/JOSE {@code kid} must be bound to the payload's issuer/holder.
 *  - A2: P-256 (ES256) JOSE signing + verification must round-trip.
 */
public class JOSESecurityParityTest {

    @AfterEach
    void resetResolver() {
        CredentialConfig.setDocumentResolver(null);
    }

    /** A2: signing a VC-JOSE with a P-256 key and verifying it must succeed. */
    @Test
    void p256_jose_sign_and_verify_roundtrip() throws Exception {
        String privHex = "2c79686425aee8002cb189bf294f2d52ca43851797c7b6e78a7dc361c4373e46";
        String issuer = "did:example:p256issuer";
        String kid = issuer + "#key-1";

        StaticDocumentResolver resolver = new StaticDocumentResolver();
        resolver.register(docWithP256(issuer, kid, privHex));
        CredentialConfig.setDocumentResolver(resolver);

        JOSECredential cred = JOSECredential.create(contents(issuer));
        cred.addProofByProvider(new P256SignerProvider(privHex));
        cred.verify();
    }

    /** A1: a token whose kid names a different DID than its issuer must be rejected. */
    @Test
    void jwt_vc_rejects_kid_from_foreign_did() throws Exception {
        String attackerPriv = "2c79686425aee8002cb189bf294f2d52ca43851797c7b6e78a7dc361c4373e46";
        String victimPriv = "1111111111111111111111111111111111111111111111111111111111111111";
        String attackerDid = "did:example:attacker";
        String victimDid = "did:example:victim";
        String attackerKid = attackerDid + "#key-1";
        String victimKid = victimDid + "#key-1";

        StaticDocumentResolver resolver = new StaticDocumentResolver();
        resolver.register(docWithSecp256k1(attackerDid, attackerKid, secpPubHex(attackerPriv)));
        resolver.register(docWithSecp256k1(victimDid, victimKid, secpPubHex(victimPriv)));
        CredentialConfig.setDocumentResolver(resolver);

        String payload = "{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],"
                + "\"type\":[\"VerifiableCredential\"],"
                + "\"issuer\":\"" + victimDid + "\","
                + "\"credentialSubject\":{\"id\":\"did:example:subject\"}}";

        // Positive control: a token legitimately signed by the victim (kid = victim's key) verifies,
        // proving the injected resolver is consulted and verification is not failing for other reasons.
        String legitInput = b64("{\"typ\":\"vc+jwt\",\"alg\":\"ES256K\",\"kid\":\"" + victimKid + "\"}")
                + "." + b64(payload);
        String legit = legitInput + "." + new JWTSigner(new DefaultSignerProvider(victimPriv)).signString(legitInput);
        JOSECredential.parse(legit).verify();

        // Attack: payload claims issuer = victim, header kid = attacker's key, signed by the attacker.
        String forgedInput = b64("{\"typ\":\"vc+jwt\",\"alg\":\"ES256K\",\"kid\":\"" + attackerKid + "\"}")
                + "." + b64(payload);
        String forged = forgedInput + "." + new JWTSigner(new DefaultSignerProvider(attackerPriv)).signString(forgedInput);
        assertThrows(Exception.class, JOSECredential.parse(forged)::verify);
    }

    private static CredentialContents contents(String issuer) {
        CredentialContents c = new CredentialContents();
        c.setContext(List.of("https://www.w3.org/ns/credentials/v2"));
        c.setTypes(List.of("VerifiableCredential"));
        c.setIssuer(issuer);
        c.setValidFrom(Instant.now());
        Subject subject = new Subject();
        subject.setId("did:example:subject");
        c.setSubject(List.of(subject));
        return c;
    }

    private static DIDDocument docWithSecp256k1(String did, String kid, String pubHex) {
        VerificationMethodEntry vm = new VerificationMethodEntry();
        vm.setId(kid);
        vm.setType("EcdsaSecp256k1VerificationKey2019");
        vm.setController(did);
        vm.setPublicKeyHex(pubHex);
        DIDDocument doc = new DIDDocument();
        doc.setId(did);
        doc.setVerificationMethod(List.of(vm));
        doc.setAssertionMethod(List.of(kid));
        doc.setAuthentication(List.of(kid));
        return doc;
    }

    private static DIDDocument docWithP256(String did, String kid, String privHex) {
        BigInteger d = new BigInteger(1, Hex.decode(stripHex(privHex)));
        ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("prime256v1");
        ECPoint q = spec.getG().multiply(d).normalize();
        JWK jwk = new JWK();
        jwk.setKty("EC");
        jwk.setCrv("P-256");
        jwk.setX(b64Url(fixed32(q.getAffineXCoord().toBigInteger())));
        jwk.setY(b64Url(fixed32(q.getAffineYCoord().toBigInteger())));

        VerificationMethodEntry vm = new VerificationMethodEntry();
        vm.setId(kid);
        vm.setType("JsonWebKey2020");
        vm.setController(did);
        vm.setPublicKeyJwk(jwk);
        DIDDocument doc = new DIDDocument();
        doc.setId(did);
        doc.setVerificationMethod(List.of(vm));
        doc.setAssertionMethod(List.of(kid));
        doc.setAuthentication(List.of(kid));
        return doc;
    }

    private static String secpPubHex(String privHex) {
        BigInteger d = new BigInteger(1, Hex.decode(stripHex(privHex)));
        ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECPoint q = spec.getG().multiply(d).normalize();
        return Hex.toHexString(q.getEncoded(false));
    }

    private static String stripHex(String h) {
        return h.startsWith("0x") ? h.substring(2) : h;
    }

    private static byte[] fixed32(BigInteger v) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[32];
        if (raw.length == 32) {
            return raw;
        }
        if (raw.length > 32) {
            System.arraycopy(raw, raw.length - 32, out, 0, 32);
        } else {
            System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
        }
        return out;
    }

    private static String b64(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    private static String b64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
