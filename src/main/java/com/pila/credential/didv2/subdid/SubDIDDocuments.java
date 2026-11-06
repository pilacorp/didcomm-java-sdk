package com.pila.credential.didv2.subdid;

import com.pila.credential.common.verificationmethod.DIDDocument;
import com.pila.credential.common.verificationmethod.VerificationMethodEntry;
import com.pila.credential.did.VerificationMethodOps;
import com.pila.credential.didv2.Documents;
import com.pila.credential.didv2.Hex;

import java.util.regex.Pattern;

public final class SubDIDDocuments {
    public static final String SUB_ID_KEY = "subId";
    private static final Pattern SUB_ID = Pattern.compile("^[A-Za-z0-9_-]{8,64}$");
    private static final Pattern DID = Pattern.compile("^did:[a-z]{1,16}(:[a-z]{1,16}){0,2}:0x[0-9a-f]{40}$");
    private static final Pattern COMPRESSED = Pattern.compile("^0x0[23][0-9a-f]{64}$");

    private SubDIDDocuments() {
    }

    public static String parseSubID(String s) throws Exception {
        if (s == null || !SUB_ID.matcher(s).matches()) {
            throw new Exception("subdid: subId must match " + SUB_ID.pattern());
        }
        return s;
    }

    public static String subDIDFor(String rootDID, String publicKeyHex) throws Exception {
        byte[] bytes = Hex.decode(publicKeyHex);
        if (!(bytes.length == 33 && (bytes[0] == 0x02 || bytes[0] == 0x03))) {
            throw new Exception("subdid: public key must be a point on secp256k1");
        }
        checkDID(rootDID);
        String addr = Documents.addressFromPublicKeyHex(publicKeyHex);
        return didPrefix(rootDID) + addr;
    }

    public static void validateSubDID(DIDDocument doc, String rootDID) throws Exception {
        if (doc == null) {
            throw new Exception("subdid: document is nil");
        }
        Documents.validateDIDDocument(doc);
        checkDID(doc.getId());
        checkDID(rootDID);
        if (!didPrefix(doc.getId()).equals(didPrefix(rootDID))) {
            throw new Exception("subdid: " + doc.getId() + " and root " + rootDID + " have different prefixes");
        }
        if (doc.getId().equals(rootDID)) {
            throw new Exception("subdid: a Sub-DID cannot be its own root");
        }
        if (!rootDID.equals(String.valueOf(doc.getController()))) {
            throw new Exception("subdid: controller \"" + doc.getController() + "\" is not the root DID " + rootDID);
        }
        if (doc.getVerificationMethod() != null) {
            for (VerificationMethodEntry vm : doc.getVerificationMethod()) {
                if (!vm.getId().startsWith(doc.getId() + "#")) {
                    throw new Exception("subdid: verification method id \"" + vm.getId() + "\" must start with "
                            + doc.getId() + "#");
                }
            }
        }
        checkPrimaryKey(doc);
        if (doc.getDidDocumentMetadata() == null) {
            throw new Exception("subdid: didDocumentMetadata is missing");
        }
    }

    public static void checkDID(String s) throws Exception {
        if (s == null || !DID.matcher(s).matches()) {
            throw new Exception("\"" + s + "\" does not match " + DID.pattern());
        }
    }

    public static String didPrefix(String s) {
        return s.substring(0, s.lastIndexOf(':') + 1);
    }

    public static String didAddress(String s) {
        return s.substring(s.lastIndexOf(':') + 1);
    }

    public static byte[] docHashBytes(DIDDocument doc) throws Exception {
        String h = Documents.hashDIDDocument(doc);
        if (!h.matches("^0x[0-9a-f]{64}$")) {
            throw new Exception("subdid: document hash \"" + h + "\" is not 32 bytes");
        }
        return Hex.decode(h);
    }

    public static String docHash(DIDDocument doc) throws Exception {
        return Documents.hashDIDDocument(doc);
    }

    private static void checkPrimaryKey(DIDDocument doc) throws Exception {
        VerificationMethodEntry vm = VerificationMethodOps.findVerificationMethod(doc, "#key-1");
        if (vm == null) {
            throw new Exception("subdid: #key-1 is missing");
        }
        if (!VerificationMethodOps.SECP256K1_VM_TYPE.equals(vm.getType())) {
            throw new Exception("subdid: #key-1 has type \"" + vm.getType() + "\", want "
                    + VerificationMethodOps.SECP256K1_VM_TYPE);
        }
        if (vm.getPublicKeyHex() == null || !COMPRESSED.matcher(vm.getPublicKeyHex()).matches()) {
            throw new Exception("subdid: #key-1 publicKeyHex must be a lowercase compressed secp256k1 key");
        }
        String address = Documents.addressFromPublicKeyHex(vm.getPublicKeyHex());
        if (!address.equals(didAddress(doc.getId()))) {
            throw new Exception("subdid: #key-1 belongs to " + address + ", not to " + doc.getId());
        }
    }
}
