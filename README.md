# didcomm-java-sdk

Java SDK for DIDComm v2 encryption, W3C Verifiable Credentials / Presentations (JSON-LD data integrity, JWT, SD-JWT/JOSE,
ecdsa-sd-2023) and the DIDv2 identifier tooling of the NDA DID network. It follows
[go-credential-sdk](https://github.com/pilacorp/go-credential-sdk), which is the reference for behaviour and test vectors.

- Maven coordinates: `com.pila:didcomm-java-sdk:1.3-SNAPSHOT` (Java 17+)
- Default DID resolver: HTTP, `https://api.ndadid.vn/api/v1/did` (`CredentialConfig.DEFAULT_BASE_URL`)
- Default DIDv2 node: `https://rpc-new.pila.vn`, chain id 704, registry `0x75e7b09a24bce5a921babe27b62ec7bfe2230d6a`

## Build and install

```bash
mvn -DskipTests package          # target/didcomm-java-sdk-1.3-SNAPSHOT.jar (demo mains are not packaged)
mvn install                      # into the local repository
```

```xml
<dependency>
  <groupId>com.pila</groupId>
  <artifactId>didcomm-java-sdk</artifactId>
  <version>1.3-SNAPSHOT</version>
</dependency>
```

Gradle (flat file): put the jar in `libs/` and use `implementation name: 'didcomm-java-sdk-1.3-SNAPSHOT'` with a `flatDir`
repository. With Maven/Gradle the runtime dependencies below are resolved transitively; on a bare classpath you must
supply them yourself.

| Needed for | Artifact |
|---|---|
| everything | `org.bouncycastle:bcprov-jdk18on:1.78.1`, `com.fasterxml.jackson.core:jackson-databind:2.17.2` |
| JSON-LD canonicalization, credentials | `com.apicatalog:titanium-json-ld:1.7.0`, `titanium-rdf-n-quads:1.0.2`, `titanium-rdfc:2.0.0`, `org.glassfish:jakarta.json:2.0.1` |
| ecdsa-sd-2023 | `com.upokecenter:cbor:5.0.0-alpha2` |

## Packages

| Package | What it is |
|---|---|
| `com.pila.didcomm` | DIDComm JWE encryption / decryption (ECDH-ES + A256GCM, secp256k1) |
| `com.pila.credential.vc` | credentials: `JSONCredential`, `JWTCredential`, `JOSECredential` (vc+jwt / vc+sd-jwt), `ECDSASDCredential`, `CredentialParser` |
| `com.pila.credential.vp` | presentations: `JSONPresentation`, `JWTPresentation`, `JOSEPresentation`, `PresentationParser` |
| `com.pila.credential.common.signer` | `SignerProvider`, `P256SignerProvider`, `RSASignerProvider`, `DefaultSignerProvider` (secp256k1), `AlgorithmProvider`, `LowS` |
| `com.pila.credential.common.verificationmethod` | DID documents, resolvers (`VerificationMethodResolver` HTTP, `StaticDocumentResolver`, `DidKeyP256Resolver`), VM selection and key decoding |
| `com.pila.credential.didv2` | DIDv2: `DIDGenerator`, `Config`, `Documents`, issuer signatures, `didcontract` (transactions, JSON-RPC), `subdid` (Sub-DIDs, `Verifier`), `did.DIDDocumentOps` (VM add / rotate / revoke) |
| `com.pila.credential.vcanchor`, `vccontract` | VC Merkle anchoring and on-chain verification |

## DIDComm encryption

```java
import com.pila.didcomm.Encryptor;
import com.pila.didcomm.Decryptor;
import com.pila.didcomm.ecdh.Secp256k1;

byte[] shared = Secp256k1.deriveSharedSecret(peerCompressedPubHex, myPrivHex);   // secp256k1 keys, hex
String jwe = Encryptor.encrypt(shared, "{\"hello\":\"world\"}");
String plain = Decryptor.decrypt(jwe, shared);
```

## Credentials

Every credential type takes the same `CredentialOptions` (`withResolver`, `withVerifyProof`, `withCheckExpiration`,
`withLeeway`, `withVerificationMethodKey`, `withBaseURL`, ...); an option a call cannot honour is refused rather than
silently ignored. The signing suite and JOSE `alg` follow the key of the verification method the proof is bound to
(P-256 -> `ecdsa-rdfc-2019` / `ES256`, secp256k1 -> `EcdsaSecp256k1Signature2019` / `ES256K`); by default the latest
active VM of the issuer for the purpose, or the one you pin with `withVerificationMethodKey("key-2")`.

### Resolving DIDs

```java
CredentialConfig.init("https://your-resolver/api/v1/did");   // default: https://api.ndadid.vn/api/v1/did (plain HTTP)
CredentialOptions opts = new CredentialOptions().withResolver(myResolver);   // per call, wins over the global config
```

Offline use and tests: `new StaticDocumentResolver(doc)` with `VerificationMethods.newDIDDocument(did, vm...)` and the VM
builders `newSecp256k1VM`, `newP256VM`, `newP256MultikeyVM`, `newRSAVM`. Offline `did:key` (P-256) resolution is opt-in:
chain `DidKeyP256Resolver` yourself.

### JSON-LD data integrity (ecdsa-rdfc-2019)

```java
CredentialContents contents = new CredentialContents();
contents.setContext(List.of("https://www.w3.org/ns/credentials/v2"));
contents.setTypes(List.of("VerifiableCredential"));
contents.setIssuer(did);
contents.setSubject(List.of(new Subject("did:example:subject", Map.of("name", "Alice"))));

JSONCredential vc = JSONCredential.newJSONCredential(contents, opts);
vc.addProofByProvider(signer, opts);                        // P-256: new P256SignerProvider(privHex)
vc.verify(new CredentialOptions().withResolver(resolver).withVerifyProof());
String json = new String(vc.getContents());
```

`docs/examples/OfflineJsonLd.java` is a complete, network-free run of this. New proofs are always built with the library
canonicalizer (native JSON types, SafeMode); the legacy "compatible" canonicalizer exists only so VCs signed long ago
still verify and must not be used to sign. Parse anything with `CredentialParser.parseCredential(bytes)` (JSON-LD, JWT,
vc+jwt / vc+sd-jwt, enveloped credentials); `parseCredentialWithValidation` also verifies.

### Signers: local key, HSM, KMS

`SignerProvider.sign(byte[] digest32)` receives the 32-byte SHA-256 digest the SDK computed and returns 64 bytes `R||S`
(or 65 with `V`). Nothing else leaves the SDK, so the private key can stay in a vault:

```java
SignerProvider kms = P256SignerProvider.fromFunc(digest -> myKms.signEs256(digest));          // P-256
SignerProvider rsa = RSASignerProvider.fromFunc(digest -> myKms.signRs256(digest), "RS256");  // JsonWebSignature2020
SignerProvider local = new P256SignerProvider(privateKeyHex);  // or (PrivateKey); low-S, 64-byte output
SignerProvider k1 = new DefaultSignerProvider(privateKeyHex);  // secp256k1
```

`AlgorithmProvider.algorithmOf(signer)` gives the JOSE algorithm a signer declares (`ES256` for `P256SignerProvider`,
the constructor argument for `RSASignerProvider`, `RS256` otherwise). `LowS.normalize(n, s)` folds a signature to low S.

### External signing (the SDK never sees the key)

```java
byte[] docHash = vc.getSigningInput();                       // digest of the canonical document
byte[] toSign  = vc.createProofSigning(docHash, proof);      // digest for this proof configuration
// ... sign `toSign` outside (64 bytes R||S) ...
proof.setProofValue(Multibase.encodeBase58Btc(signature));
vc.addCustomProof(proof);
```

`docs/examples/ExternalSigning.java` shows it end to end (the proof carries type, cryptosuite, verificationMethod,
proofPurpose and created).

### JWT and JOSE (vc+jwt, vc+sd-jwt)

- `JWTCredential`: VC 1.1 JWT (`vc` claim). SD-JWT is refused here (`SDJWTRequiresJOSEException`).
- `JOSECredential`: VC 2.0 secured with JOSE; selective disclosure via options.

```java
CredentialOptions sd = new CredentialOptions().withSDSelectivePaths(List.of("credentialSubject.name"));
JOSECredential vc = JOSECredential.create(contents, sd);
vc.addProofByProvider(signer, sd);
String sdJwt = (String) vc.serialize();                      // header.payload.signature~disclosure~
JOSECredential shown = vc.present(List.of(/* disclosures to reveal */));
```

### Selective disclosure for JSON-LD (ecdsa-sd-2023)

```java
ECDSASDCredential base = ECDSASDCredential.newECDSASDCredential(contents, opts);
base.addProofByProvider(p256Signer, List.of("/issuer"), opts);       // mandatory JSON pointers
JSONCredential derived = base.derive(List.of("/credentialSubject/name"));
```

### Presentations

```java
PresentationContents pc = new PresentationContents();
pc.setContext(List.of("https://www.w3.org/ns/credentials/v2"));
pc.setTypes(List.of("VerifiablePresentation"));
pc.setHolder(holderDid);
pc.setVerifiableCredentials(List.of(vc));

PresentationOptions popts = new PresentationOptions().withChallenge(nonce).withDomain("https://verifier.example");
JSONPresentation vp = JSONPresentation.create(pc, popts);      // also JWTPresentation / JOSEPresentation (vp+jwt)
vp.addProofByProvider(holderSigner, popts);

PresentationOptions check = new PresentationOptions().withVerifyProof()
    .withExpectedChallenge(nonce).withExpectedDomain("https://verifier.example").withVCValidation();
PresentationParser.parsePresentation(bytes).verify(check);
```

`withChallenge` / `withDomain` bind the proof (JSON-LD) or the `nonce` / `aud` claims (JWT / JOSE) at signing;
`withExpectedChallenge` / `withExpectedDomain` are checked on verification; `withRequireAudience()` refuses an
unbound presentation.

## DIDv2

```java
Signer issuer = new DefaultProvider(issuerPrivHex);             // any didv2.Signer works (HSM, KMS)
DIDGenerator gen = new DIDGenerator(Config.withIssuerSignerProvider(issuer), Config.withSyncEpoch(true),
                                    Config.withSyncNonce(true));   // reads the capability epoch and the nonce over JSON-RPC
DIDGenerator.DIDTxResult r = gen.generateDID(DIDType.PEOPLE, "", Map.of("name", "alice"),
                                             Config.withP256VerificationMethod());   // also publish the P-256 key at #key-2
// r.did, r.document, r.transaction.txHex (eth_sendRawTransaction it yourself), r.secret.privateKeyHex
```

Options are `Config.with*` consumers (`withRPC`, `withDIDChainID`, `withDIDAddressSMC`, `withMethod`, `withEpoch`,
`withNonce`, `withCapID`, `withSyncEpoch`, `withSyncNonce`, `withIssuerSignerProvider`, `withDIDSignerProvider`,
`withVerificationMethods`, `withP256VerificationMethod`, `withDIDConfig`); pass them to the constructor and/or per call.
A capability id is generated when you do not set one. Offline, give `withEpoch` / `withNonce` instead of syncing; tests
can inject the node with `Config.withChainClient(client)` (`JsonRpcClient(url, transport)` takes a stub transport).
`generateDIDTX`, `generateIssuerSignature`, `generateSetDocumentHashTransaction`,
`generateSetDocumentHashByIssuerTransaction` cover the split issuer / owner deployments.

Key management on a document (`com.pila.credential.didv2.did.DIDDocumentOps`): `addVerificationMethod`,
`rotateVerificationMethod`, `revokeVerificationMethod`, `addVerificationMethodPurposes`,
`removeVerificationMethodPurposes`. A revoked VM stays in the document, `revoked` is written as RFC 3339 with
nanoseconds, and `Documents.hashDIDDocument(doc)` is the on-chain document hash (JCS + Keccak-256).
`docs/examples/DidV2.java` runs create, rotate, revoke and re-anchor offline.

Sub-DIDs: `GenerateSubDID.generate(...)` builds one under a root DID; `Verifier.verifySubDID(...)` checks a proof from
`GET /api/v3/sub-did/{did}/proof` against the chain (chain id, receipt, writer anchor, Merkle path, revoked leaf,
writer role). It returns `ACTIVE`, `REVOKED` or `INVALID` with a reason, and throws `SubDIDException` when the chain cannot
be read. See `docs/examples/SubDidVerify.java`.

## Examples

`docs/examples/*.java` are plain sources (not part of the build). Compile and run against the built classes:

```bash
mvn -q compile dependency:build-classpath -Dmdep.outputFile=/tmp/cp.txt
javac -d /tmp/ex -cp "target/classes:$(cat /tmp/cp.txt)" docs/examples/*.java
java -cp "/tmp/ex:target/classes:$(cat /tmp/cp.txt)" OfflineJsonLd      # or DidV2
```

## Notes

- Keys: secp256k1 for DIDComm and DIDv2 transactions; P-256 for credential and presentation proofs (Multikey `publicKeyMultibase`, or JWK).
- JWE JSON produced here uses `ECDH-ES` and `A256GCM`.
- `Processor.canonicalizeDocument` (the compatible canonicalizer) is for verifying legacy credentials only.
