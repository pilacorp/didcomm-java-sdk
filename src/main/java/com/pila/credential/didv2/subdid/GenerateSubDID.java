package com.pila.credential.didv2.subdid;

import com.pila.credential.common.verificationmethod.DIDDocument;
import com.pila.credential.didv2.Documents;
import com.pila.credential.didv2.Hex;
import com.pila.credential.didv2.Signer;
import com.pila.credential.didv2.Types;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public final class GenerateSubDID {
    private GenerateSubDID() {
    }

    public static final class Result {
        public String did;
        public DIDDocument document;
        public String type;
        public String signature;
    }

    public static Result generate(String rootDID, String subID, String subPublicKeyHex, int didType,
            Map<String, Object> metadata, Signer rootSigner, Signer subSigner, List<Documents.VmSpec> extraVMs)
            throws Exception {
        if (rootSigner == null || subSigner == null) {
            throw new Exception("subdid: root signer and Sub-DID signer are required");
        }
        if ("unknown".equals(Types.didTypeString(didType))) {
            throw new Exception("subdid: unknown DID type " + didType);
        }
        SubDIDDocuments.parseSubID(subID);
        byte[] pubBytes = Hex.decode(subPublicKeyHex);
        if (pubBytes.length != 33) {
            throw new Exception("subdid: Sub-DID public key: expected compressed secp256k1");
        }
        String subDID = SubDIDDocuments.subDIDFor(rootDID, subPublicKeyHex);
        byte[] consent = SubDIDSignatures.signRootConsent(subDID, rootSigner);
        Map<String, Object> docMetadata = new TreeMap<>();
        if (metadata != null) {
            docMetadata.putAll(metadata);
        }
        docMetadata.put(SubDIDDocuments.SUB_ID_KEY, subID);
        DIDDocument doc = Documents.generateDIDDocument(subPublicKeyHex, subDID, "", rootDID, didType, docMetadata,
                extraVMs == null ? new ArrayList<>() : extraVMs);
        SubDIDSignatures.setRootConsent(doc, consent);
        SubDIDDocuments.validateSubDID(doc, rootDID);
        try {
            SubDIDSignatures.verifyRootConsent(doc, rootDID);
        } catch (Exception e) {
            throw new Exception("subdid: the root signer does not hold the primary key of " + rootDID + ": "
                    + e.getMessage(), e);
        }
        byte[] sig = SubDIDSignatures.signDocument(doc, subSigner);
        try {
            SubDIDSignatures.verifyDocumentSignature(doc, sig);
        } catch (Exception e) {
            throw new Exception("subdid: the Sub-DID signer does not hold the key of " + subDID + ": " + e.getMessage(),
                    e);
        }
        Result r = new Result();
        r.did = subDID;
        r.document = doc;
        r.type = Types.didTypeString(didType);
        r.signature = Hex.encode0x(sig);
        return r;
    }
}
