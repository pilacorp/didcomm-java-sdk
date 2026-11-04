package com.pila.credential.common.jsonmap;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pila.credential.common.processor.Processor;
import com.pila.credential.common.verificationmethod.DIDDocument;
import com.pila.credential.common.verificationmethod.JWK;
import com.pila.credential.common.verificationmethod.StaticDocumentResolver;
import com.pila.credential.common.verificationmethod.VerificationMethodEntry;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Blocking review finding A3: new ecdsa-rdfc-2019 proofs must use the library
 * canonicalizer (native JSON number types), not the legacy "compatible" one that
 * coerces numbers to xsd:string. A compatible-canonicalized numeric claim does not
 * interoperate with go-credential-sdk.
 *
 * <p>The fixture {@code go-interop/numeric-rdfc-2019.json} was produced by
 * go-credential-sdk signing a VC whose subject carries an integer and a decimal.
 */
public class GoNumericCanonicalizationTest {

    // Same P-256 key the Go fixture generator used, so the issuer document matches.
    private static final String PRIV = "2c79686425aee8002cb189bf294f2d52ca43851797c7b6e78a7dc361c4373e46";
    private static final String DID = "did:example:gonumeric";
    private static final String KID = DID + "#key-1";

    @Test
    void javaVerifiesGoSignedNumericRdfcCredential() throws Exception {
        String json = new String(getClass().getResourceAsStream("/go-interop/numeric-rdfc-2019.json").readAllBytes(),
                StandardCharsets.UTF_8);
        JSONMap map = new ObjectMapper().readValue(json, JSONMap.class);

        StaticDocumentResolver resolver = new StaticDocumentResolver();
        resolver.register(issuerDoc());

        assertTrue(map.verifyProof(resolver), "Go-signed numeric ecdsa-rdfc-2019 VC must verify in Java");
    }

    /**
     * Locks the canonicalizer choice: a numeric value becomes a native xsd:integer in the
     * library canonicalizer but an xsd:string in the legacy compatible one. Reverting the
     * signing path to the compatible canonicalizer would break Go interop and this test.
     */
    @Test
    void libraryCanonicalizerKeepsNativeNumberTypes() throws Exception {
        Map<String, Object> doc = Map.of(
                "@context", List.of("https://www.w3.org/ns/credentials/v2",
                        "https://www.w3.org/ns/credentials/examples/v2"),
                "type", "VerifiableCredential",
                "issuer", DID,
                "credentialSubject", Map.of("id", "did:example:subject", "age", 30));

        String library = new String(Processor.canonicalizeDocumentNativeTypes(doc), StandardCharsets.UTF_8);
        String compatible = new String(Processor.canonicalizeDocument(doc), StandardCharsets.UTF_8);

        // Library keeps the native integer type; the legacy compatible canonicalizer coerces
        // it to a string literal, so the two produce different signing input for any number.
        assertTrue(library.contains("XMLSchema#integer"), "native number must canonicalize as xsd:integer");
        assertFalse(compatible.contains("XMLSchema#integer"), "compatible canonicalizer must not keep the integer type");
        assertFalse(library.equals(compatible), "the two canonicalizers must differ on numeric claims");
    }

    private static DIDDocument issuerDoc() {
        BigInteger d = new BigInteger(1, Hex.decode(PRIV));
        ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("prime256v1");
        ECPoint q = spec.getG().multiply(d).normalize();
        JWK jwk = new JWK();
        jwk.setKty("EC");
        jwk.setCrv("P-256");
        jwk.setX(b64Url(fixed32(q.getAffineXCoord().toBigInteger())));
        jwk.setY(b64Url(fixed32(q.getAffineYCoord().toBigInteger())));

        VerificationMethodEntry vm = new VerificationMethodEntry();
        vm.setId(KID);
        vm.setType("JsonWebKey2020");
        vm.setController(DID);
        vm.setPublicKeyJwk(jwk);
        DIDDocument doc = new DIDDocument();
        doc.setId(DID);
        doc.setVerificationMethod(List.of(vm));
        doc.setAssertionMethod(List.of(KID));
        doc.setAuthentication(List.of(KID));
        return doc;
    }

    private static byte[] fixed32(BigInteger v) {
        byte[] raw = v.toByteArray();
        if (raw.length == 32) {
            return raw;
        }
        byte[] out = new byte[32];
        if (raw.length > 32) {
            System.arraycopy(raw, raw.length - 32, out, 0, 32);
        } else {
            System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
        }
        return out;
    }

    private static String b64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
