import com.pila.credential.common.dto.Proof;
import com.pila.credential.common.signer.P256SignerProvider;
import com.pila.credential.common.util.Multibase;
import com.pila.credential.vc.JSONCredential;

/**
 * External signing of a JSON-LD credential: the SDK produces the 32-byte digest, the key lives elsewhere (HSM, KMS,
 * a hardware wallet) and returns the 64-byte R||S signature, the SDK attaches it.
 */
public class ExternalSigning {
    static void sign(JSONCredential unsigned, String vmUrl, P256SignerProvider kms) throws Exception {
        Proof proof = new Proof();
        proof.setType("DataIntegrityProof");
        proof.setCryptosuite("ecdsa-rdfc-2019");
        proof.setVerificationMethod(vmUrl);
        proof.setProofPurpose("assertionMethod");
        proof.setCreated("2026-01-01T00:00:00Z");

        byte[] docHash = unsigned.getSigningInput();                    // digest of the canonical document
        byte[] toSign = unsigned.createProofSigning(docHash, proof);   // digest of docHash + proof options
        byte[] signature = kms.sign(toSign);                           // 64 bytes R||S, low S

        proof.setProofValue(Multibase.encodeBase58Btc(signature));     // "z..." base58btc
        unsigned.addCustomProof(proof);
    }
}
