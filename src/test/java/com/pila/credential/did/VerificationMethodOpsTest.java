package com.pila.credential.did;

import com.pila.credential.common.verificationmethod.DIDDocument;
import com.pila.credential.common.verificationmethod.Multikey;
import com.pila.credential.common.verificationmethod.VerificationMethodEntry;
import com.pila.credential.didv2.Documents;
import com.pila.credential.didv2.Hex;
import com.pila.credential.didv2.Secp256k1;
import com.pila.credential.didv2.Types;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class VerificationMethodOpsTest {
    private static final String DID = "did:nda:0x0000000000000000000000000000000000000001";

    private static String secpHex(int seed) {
        byte[] priv = new byte[32];
        java.util.Arrays.fill(priv, (byte) seed);
        priv[31] = (byte) seed;
        return Hex.encode0x(Secp256k1.publicFromPrivate(priv, true));
    }

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static DIDDocument baseDoc() throws Exception {
        return Documents.generateDIDDocument(secpHex(1), DID, "", "did:nda:0xissuer", Types.DID_TYPE_PEOPLE, null, List.of());
    }

    @Test
    void addsSequentialIdsCopiesPurposesOnRotateAndKeepsRevokedVMs() throws Exception {
        DIDDocument doc = baseDoc();
        VerificationMethodEntry vm2 = new VerificationMethodEntry();
        vm2.setPublicKeyHex(secpHex(2));
        String id2 = VerificationMethodOps.addVerificationMethod(doc, vm2, List.of(VerificationPurpose.AUTHENTICATION));
        assertEquals(DID + "#key-2", id2);
        assertTrue(doc.getAuthentication().contains(id2));

        VerificationMethodEntry vm3 = new VerificationMethodEntry();
        vm3.setPublicKeyHex(secpHex(3));
        String newId = VerificationMethodOps.rotateVerificationMethod(doc, DID + "#key-1", vm3, null, Instant.now());
        assertEquals(DID + "#key-3", newId);
        VerificationMethodEntry old = VerificationMethodOps.findVerificationMethod(doc, DID + "#key-1");
        assertNotNull(old.getRevoked());
        assertEquals("superseded", old.getRevocationReason());
        assertTrue(doc.getAuthentication().contains(newId));
        assertTrue(doc.getAssertionMethod().contains(newId));
        assertNotNull(VerificationMethodOps.findVerificationMethod(doc, DID + "#key-1"));
        assertTrue(doc.getContext().contains(VerificationMethodOps.CID_CONTEXT));
    }

    @Test
    void rejectsDuplicateIdsSecondRevokeAndNewPurposesOnRevokedVMs() throws Exception {
        DIDDocument doc = baseDoc();
        VerificationMethodEntry dup = new VerificationMethodEntry();
        dup.setId("#key-1");
        dup.setPublicKeyHex(secpHex(2));
        assertThrows(Exception.class, () -> VerificationMethodOps.addVerificationMethod(doc, dup, List.of()));
        VerificationMethodOps.revokeVerificationMethod(doc, "#key-1", "compromised", Instant.now());
        assertThrows(Exception.class, () -> VerificationMethodOps.revokeVerificationMethod(doc, "#key-1", "again", Instant.now()));
        assertThrows(Exception.class, () -> VerificationMethodOps.addVerificationMethodPurposes(doc, "#key-1",
                List.of(VerificationPurpose.AUTHENTICATION)));
    }

    @Test
    void dedupesPurposeRefsAndAddsCidContextForMultikey() throws Exception {
        DIDDocument doc = baseDoc();
        VerificationMethodOps.addVerificationMethodPurposes(doc, "#key-1",
                List.of(VerificationPurpose.AUTHENTICATION, VerificationPurpose.ASSERTION_METHOD));
        assertEquals(1, doc.getAuthentication().size());

        var spec = ECNamedCurveTable.getParameterSpec("prime256v1");
        var kpg = java.security.KeyPairGenerator.getInstance("EC", "BC");
        kpg.initialize(spec, new SecureRandom());
        var kp = kpg.generateKeyPair();
        byte[] uncompressed = ((org.bouncycastle.jce.interfaces.ECPublicKey) kp.getPublic()).getQ().getEncoded(false);
        byte[] xy = java.util.Arrays.copyOfRange(uncompressed, 1, 65);
        VerificationMethodEntry p256 = new VerificationMethodEntry();
        p256.setPublicKeyMultibase(Multikey.encodeP256PublicXY(xy));
        String id = VerificationMethodOps.addVerificationMethod(doc, p256, List.of(VerificationPurpose.ASSERTION_METHOD));
        assertEquals(DID + "#key-2", id);
        assertTrue(doc.getContext().contains(VerificationMethodOps.CID_CONTEXT));
        VerificationMethodOps.removeVerificationMethodPurposes(doc, "#key-2", List.of(VerificationPurpose.ASSERTION_METHOD));
        assertTrue(!doc.getAssertionMethod().contains(id));
    }

    @Test
    void addPurposesNormalizesFragmentToFullUrl() throws Exception {
        DIDDocument doc = baseDoc();
        VerificationMethodEntry vm = new VerificationMethodEntry();
        vm.setPublicKeyHex(secpHex(2));
        String id = VerificationMethodOps.addVerificationMethod(doc, vm, List.of());
        VerificationMethodOps.addVerificationMethodPurposes(doc, "#key-2", List.of(VerificationPurpose.AUTHENTICATION));
        long count = doc.getAuthentication().stream().filter(id::equals).count();
        assertEquals(1, count);
        for (String ref : doc.getAuthentication()) {
            assertTrue(ref.startsWith(DID + "#"));
        }
    }
}
