# Migrating from `dev` (1.2.x) to this branch (1.3)

Behaviour that changes for existing callers. The library follows `go-credential-sdk`; where the two differed, Java now does what Go does.

| Area | Before (`dev`) | Now | What to do |
|---|---|---|---|
| `JSONCredential.addProof(hex)` / `JSONPresentation.addProof(hex)` | signed with a secp256k1 key | signs with a **P-256** key (Go `AddProof`) | A secp256k1 hex key now fails at run time. For secp256k1 use `addProofByProvider(new DefaultSignerProvider(hex))`. |
| Signing methods | on `Credential` | on `SignableCredential`; JWT/JOSE no longer throw `UnsupportedOperationException` from `createProofSigning` | Declare variables as `SignableCredential` where you sign. |
| `vp.VerifiablePresentation` | present | **removed**; use `JSONPresentation` / `JWTPresentation` (shared `Presentation` type) | Replace the type and its factory calls. |
| Default `kid` / verification method | pinned `key-1` | the only VM, else the latest active VM of the purpose; pin with `withVerificationMethodKey` | Pass the key explicitly if you relied on `key-1`. |
| `createProofSigning` (JSON VC) | returned the 64-byte hash data | returns the 32-byte SHA-256 of it | Sign the 32 bytes. |
| New proofs | legacy canonicalizer | library canonicalizer (SafeMode, relative IRIs refused); legacy proofs still verify | None for verification. |
| JWT / JOSE `alg` | hard-coded `ES256K` | chosen by the key kind (`ES256` for P-256) | None. |
| `credentialStatus`, schema, validity | not checked | checked under the matching options (`withCheckRevocation`, `withSchemaValidation`, `withCheckExpiration`) | Opt in where you need them. |
| Errors | plain `Exception` | typed exceptions in places (`CredentialException`, `AlreadyRevokedException`, `IssuerNotSupportedException`, `BoundedHttp.Failure`, ...) | Catch the specific type if you matched on message text. |

The artifact version stays `1.3-SNAPSHOT`; tag a major/minor release when this lands, since the table above is not source-compatible.
