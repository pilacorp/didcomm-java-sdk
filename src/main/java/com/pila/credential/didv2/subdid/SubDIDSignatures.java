package com.pila.credential.didv2.subdid;

import com.pila.credential.common.verificationmethod.DIDDocument;
import com.pila.credential.didv2.Documents;
import com.pila.credential.didv2.Ethereum;
import com.pila.credential.didv2.Hex;
import com.pila.credential.didv2.Secp256k1;
import com.pila.credential.didv2.Signer;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;

public final class SubDIDSignatures {
    public static final String ROOT_CONSENT_PREFIX = "Sub-DID ";
    static final String ROOT_CONSENT_KEY = "rootConsent";
    private static final Pattern STORED = Pattern.compile("^0x[0-9a-f]{130}$");

    private SubDIDSignatures() {
    }

    public static byte[] normalizeSignature(byte[] sig) throws Exception {
        if (sig.length != 65) {
            throw new Exception("subdid: signature is " + sig.length + " bytes, want 65");
        }
        byte[] out = Arrays.copyOf(sig, 65);
        int v = out[64] & 0xff;
        switch (v) {
            case 0, 1 -> out[64] = (byte) (v + 27);
            case 27, 28 -> {
            }
            default -> throw new Exception("subdid: signature v = " + v + ", want 0, 1, 27 or 28");
        }
        if (new BigInteger(1, Arrays.copyOfRange(out, 32, 64)).compareTo(Secp256k1.HALF_N) > 0) {
            throw new Exception("subdid: signature s is above n/2");
        }
        return out;
    }

    public static byte[] rootConsentDigest(String subDID) {
        return Ethereum.personalSignDigest(ROOT_CONSENT_PREFIX + subDID);
    }

    public static byte[] signRootConsent(String subDID, Signer root) throws Exception {
        SubDIDDocuments.checkDID(subDID);
        if (root == null) {
            throw new Exception("subdid: root signer is nil");
        }
        return normalizeSignature(root.sign(rootConsentDigest(subDID)));
    }

    public static void setRootConsent(DIDDocument doc, byte[] sig) throws Exception {
        if (doc == null) {
            throw new Exception("subdid: document is nil");
        }
        byte[] normalized = normalizeSignature(sig);
        Map<String, Object> meta = new TreeMap<>();
        if (doc.getDidDocumentMetadata() != null) {
            meta.putAll(doc.getDidDocumentMetadata());
        }
        meta.put(ROOT_CONSENT_KEY, Hex.encode0x(normalized));
        doc.setDidDocumentMetadata(Documents.sortObject(meta));
    }

    public static byte[] getRootConsent(DIDDocument doc) throws Exception {
        if (doc == null) {
            throw new Exception("subdid: root consent invalid: document is nil");
        }
        Object value = doc.getDidDocumentMetadata() == null ? null : doc.getDidDocumentMetadata().get(ROOT_CONSENT_KEY);
        if (value == null) {
            throw new Exception("subdid: root consent invalid: rootConsent is missing");
        }
        if (!(value instanceof String s) || !STORED.matcher(s).matches()) {
            throw new Exception(
                    "subdid: root consent invalid: rootConsent must be 0x followed by 130 lowercase hex characters");
        }
        byte[] sig = Hex.decode(s);
        int v = sig[64] & 0xff;
        if (v != 27 && v != 28) {
            throw new Exception("subdid: root consent invalid: rootConsent v = " + v + ", want 27 or 28");
        }
        normalizeSignature(sig);
        return sig;
    }

    public static void verifyRootConsent(DIDDocument subDoc, String rootDID) throws Exception {
        byte[] sig = getRootConsent(subDoc);
        SubDIDDocuments.checkDID(rootDID);
        SubDIDDocuments.checkDID(subDoc.getId());
        checkSigner(rootConsentDigest(subDoc.getId()), sig, SubDIDDocuments.didAddress(rootDID));
    }

    public static byte[] signatureDigest(byte[] documentHash32) {
        return Ethereum.personalSignDigest(documentHash32);
    }

    public static byte[] signDocument(DIDDocument doc, Signer sub) throws Exception {
        if (sub == null) {
            throw new Exception("subdid: Sub-DID signer is nil");
        }
        byte[] h = SubDIDDocuments.docHashBytes(doc);
        return normalizeSignature(sub.sign(signatureDigest(h)));
    }

    public static void verifyDocumentSignature(DIDDocument doc, byte[] sig) throws Exception {
        byte[] normalized = normalizeSignature(sig);
        if (doc == null) {
            throw new Exception("subdid: sub-DID signature invalid: document is nil");
        }
        byte[] h = SubDIDDocuments.docHashBytes(doc);
        checkSigner(signatureDigest(h), normalized, SubDIDDocuments.didAddress(doc.getId()));
    }

    private static void checkSigner(byte[] digest, byte[] storedSig, String address) throws Exception {
        byte[] pub = Secp256k1.recoverPublic(digest, storedSig);
        String recovered = Secp256k1.addressFromPublicKey(pub);
        if (!recovered.equalsIgnoreCase(address)) {
            throw new Exception("signed by " + recovered + ", not by " + address);
        }
    }
}
