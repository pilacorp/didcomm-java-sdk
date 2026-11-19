import com.pila.credential.common.signer.P256SignerProvider;
import com.pila.credential.common.verificationmethod.DIDDocument;
import com.pila.credential.common.verificationmethod.StaticDocumentResolver;
import com.pila.credential.common.verificationmethod.VerificationMethodEntry;
import com.pila.credential.common.verificationmethod.VerificationMethods;
import com.pila.credential.vc.CredentialContents;
import com.pila.credential.vc.CredentialOptions;
import com.pila.credential.vc.JSONCredential;
import com.pila.credential.vc.Subject;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.List;
import java.util.Map;

/**
 * Issue and verify a JSON-LD credential (ecdsa-rdfc-2019, P-256) without any network: the issuer DID document is
 * served by an in-memory StaticDocumentResolver. Compile and run: see "Examples" in the README.
 */
public class OfflineJsonLd {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");
        g.initialize(new ECGenParameterSpec("prime256v1"));
        KeyPair kp = g.generateKeyPair();

        // The issuer publishes its P-256 key as a Multikey verification method.
        String did = "did:example:issuer";
        VerificationMethodEntry vm = VerificationMethods.newP256MultikeyVM(did, "key-1", (ECPublicKey) kp.getPublic());
        DIDDocument doc = VerificationMethods.newDIDDocument(did, vm);
        CredentialOptions opts = new CredentialOptions().withResolver(new StaticDocumentResolver(doc));

        CredentialContents contents = new CredentialContents();
        contents.setContext(List.of("https://www.w3.org/ns/credentials/v2"));
        contents.setTypes(List.of("VerifiableCredential"));
        contents.setIssuer(did);
        contents.setSubject(List.of(new Subject("did:example:subject", Map.of())));

        JSONCredential vc = JSONCredential.newJSONCredential(contents, opts);
        // Any SignerProvider works here: a local key, or P256SignerProvider.fromFunc(digest -> kms.sign(digest)).
        vc.addProofByProvider(new P256SignerProvider(kp.getPrivate()), opts);
        vc.verify(new CredentialOptions().withResolver(new StaticDocumentResolver(doc)).withVerifyProof());

        System.out.println(new String(vc.getContents()));
    }
}
