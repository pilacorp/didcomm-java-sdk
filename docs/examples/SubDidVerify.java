import com.pila.credential.common.verificationmethod.DIDDocument;
import com.pila.credential.didv2.didcontract.JsonRpcClient;
import com.pila.credential.didv2.subdid.ProofResponse;
import com.pila.credential.didv2.subdid.SubDIDException;
import com.pila.credential.didv2.subdid.Verifier;

/** Verify a Sub-DID against the chain that anchored it. Needs a reachable node, so this only compiles in CI. */
public class SubDidVerify {
    static Verifier.Result verify(String subDid, DIDDocument document, String proofJson) throws Exception {
        Verifier verifier = new Verifier(new Verifier.Chain("did", 704,
                "0x75e7b09a24bce5a921babe27b62ec7bfe2230d6a", new JsonRpcClient("https://rpc-new.pila.vn")));
        Verifier.VerifyRequest req = new Verifier.VerifyRequest();
        req.subDID = subDid;
        req.document = document; // optional: without it only a deactivated (revoked) leaf can be proven
        req.proof = ProofResponse.fromJson(proofJson); // GET /api/v3/sub-did/{did}/proof
        req.chain = "did";
        try {
            Verifier.Result res = verifier.verifySubDID(req);
            // ACTIVE, REVOKED, or INVALID with res.reason (e.g. writer_revoked)
            System.out.println(res.status + " " + (res.reason == null ? "" : res.reason.code));
            return res;
        } catch (SubDIDException e) {
            // not anchored yet / chain unreachable / wrong chain id: no verdict
            System.out.println(e.kind() + ": " + e.getMessage());
            throw e;
        }
    }
}
