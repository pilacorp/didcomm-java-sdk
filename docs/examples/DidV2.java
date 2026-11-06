import com.pila.credential.common.verificationmethod.DIDDocument;
import com.pila.credential.common.verificationmethod.VerificationMethodEntry;
import com.pila.credential.didv2.Config;
import com.pila.credential.didv2.DIDGenerator;
import com.pila.credential.didv2.DIDType;
import com.pila.credential.didv2.DefaultProvider;
import com.pila.credential.didv2.Documents;
import com.pila.credential.didv2.KeyPair;
import com.pila.credential.didv2.did.DIDDocumentOps;
import com.pila.credential.didv2.didcontract.LegacyTx;

import java.time.Instant;
import java.util.Map;

/**
 * DIDv2: create a DID (raw transaction, nothing is submitted), rotate and revoke a key, anchor the new document
 * hash. Offline run: nonce and epoch are given; for a live node add Config.withSyncEpoch(true) and
 * Config.withSyncNonce(true) (reads eth_call getCapabilityEpoch and eth_getTransactionCount from Config.withRPC).
 */
public class DidV2 {
    public static void main(String[] args) throws Exception {
        DefaultProvider issuer = new DefaultProvider("11".repeat(32)); // issuer key (or any didv2.Signer: HSM, KMS)
        DIDGenerator generator = new DIDGenerator(
                Config.withIssuerSignerProvider(issuer), Config.withEpoch(0), Config.withNonce(0));

        // 1. New DID: key pair, DID document (#key-1 secp256k1, #key-2 P-256 Multikey), issuer signature, signed tx.
        DIDGenerator.DIDTxResult created = generator.generateDID(DIDType.PEOPLE, "", Map.of("name", "alice"),
                Config.withP256VerificationMethod());
        System.out.println("did      " + created.did);
        System.out.println("raw tx   " + created.transaction.txHex); // eth_sendRawTransaction
        System.out.println("secret   " + created.secret.privateKeyHex.substring(0, 6) + "...");

        // 2. Rotate #key-1 to a new key: the old VM stays, marked revoked (RFC3339Nano); the new one gets its purposes.
        DIDDocument doc = created.document;
        VerificationMethodEntry next = new VerificationMethodEntry();
        KeyPair fresh = Documents.generateECDSAKeyPair();
        next.setPublicKeyHex(fresh.publicKeyHex);
        String newId = DIDDocumentOps.rotateVerificationMethod(doc, "#key-1", next, "superseded", Instant.now());

        // 3. Revoke #key-2 outright (a hard reason invalidates everything it ever signed).
        DIDDocumentOps.revokeVerificationMethod(doc, "#key-2", "keyCompromise", Instant.now());

        // 4. Anchor the updated document: the issuer signs setDocumentHashByIssuer(did, hash).
        String docHash = Documents.hashDIDDocument(doc);
        LegacyTx.Signed update = generator.generateSetDocumentHashByIssuerTransaction(docHash,
                Documents.addressFromPublicKeyHex(doc.getVerificationMethod().get(0).getPublicKeyHex()),
                Config.withNonce(1));
        System.out.println("new key  " + newId);
        System.out.println("doc hash " + docHash);
        System.out.println("update   " + update.txHash);
    }
}
