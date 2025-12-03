didcomm-java-sdk

Quick guide for distributing and consuming the JAR.

Build the JAR

- mvn -DskipTests package
- Artifact (built by Maven): target/didcomm-java-sdk-1.0-SNAPSHOT.jar
- If you moved the JAR to repo root: ./didcomm-java-sdk-1.0-SNAPSHOT.jar

Give the JAR to your partner

- Share the JAR file (now at repo root): ./didcomm-java-sdk-1.0-SNAPSHOT.jar

Partner setup options

- Maven (install to local repo):

  - mvn install:install-file -Dfile=./didcomm-java-sdk-1.0-SNAPSHOT.jar -DgroupId=com.pila -DartifactId=didcomm-java-sdk -Dversion=1.0-SNAPSHOT -Dpackaging=jar
  - Then add dependency in their pom.xml:
    <dependency>
    <groupId>com.pila</groupId>
    <artifactId>didcomm-java-sdk</artifactId>
    <version>1.0-SNAPSHOT</version>
    </dependency>

- Gradle (flat file lib):

  - settings.gradle: none required
  - build.gradle:
    repositories { flatDir { dirs 'libs' } }
    dependencies { implementation name: 'didcomm-java-sdk-1.0-SNAPSHOT' }
  - Place the JAR in project/libs/

- Direct classpath (apps/scripts):
  - java -cp ./didcomm-java-sdk-1.0-SNAPSHOT.jar:bcprov-jdk18on-1.78.1.jar:jackson-databind-2.17.2.jar YourMain

Runtime dependencies (partner must include)

- org.bouncycastle:bcprov-jdk18on:1.78.1
- com.fasterxml.jackson.core:jackson-databind:2.17.2

Minimal usage example

```java
import com.pila.didcomm.Encryptor;
import com.pila.didcomm.Decryptor;
import com.pila.didcomm.ecdh.Secp256k1;

public class Demo {
  public static void main(String[] args) {
    String pubHex = "039c2283702214062a04efb6707db8308ff566c38f93adb93193b175d4f9b354b7";
    String privHex = "2c79686425aee8002cb189bf294f2d52ca43851797c7b6e78a7dc361c4373e46";
    String message = "{\"hello\":\"world\"}";

    byte[] shared = Secp256k1.deriveSharedSecret(pubHex, privHex);
    String jwe = Encryptor.encrypt(shared, message);
    String plain = Decryptor.decrypt(jwe, shared);

    System.out.println(jwe);
    System.out.println(plain);
  }
}
```

Decrypting an incoming JWE

```java
import com.pila.didcomm.Decryptor;
import com.pila.didcomm.ecdh.Secp256k1;

// 1) Derive shared key (secp256k1 compressed pubkey hex, 32-byte privkey hex)
byte[] shared = Secp256k1.deriveSharedSecret(senderPubHex, receiverPrivHex);

// 2) Decrypt a JWE JSON (fields: protected, iv, ciphertext, tag)
String plaintext = Decryptor.decrypt(jweJsonString, shared);
System.out.println(plaintext);
```

JSON-LD Canonicalization

Canonicalize JSON-LD documents for signing or hashing:

```java
import com.pila.credential.common.processor.Processor;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;

// Parse JSON string to Map
String jsonString = "{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],\"type\":\"VerifiableCredential\",\"issuer\":\"did:example:123\",\"credentialSubject\":{\"id\":\"did:example:456\"}}";
ObjectMapper mapper = new ObjectMapper();
Map<String, Object> doc = mapper.readValue(jsonString, Map.class);

// Canonicalize the document (returns canonical N-Quads as bytes)
byte[] canonicalBytes = Processor.canonicalizeDocument(doc);
String canonicalNQuads = new String(canonicalBytes);
System.out.println("Canonical N-Quads:\n" + canonicalNQuads);

// Compute SHA-256 digest of canonical form
byte[] digest = Processor.computeDigest(canonicalBytes);
System.out.println("Digest: " + bytesToHex(digest));

// Helper method to convert bytes to hex
private static String bytesToHex(byte[] bytes) {
    StringBuilder sb = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) sb.append(String.format("%02x", b));
    return sb.toString();
}
```

**Use cases:**
- Generate deterministic hashes for JSON-LD documents
- Create signing input for Data Integrity Proofs
- Compare JSON-LD documents in canonical form

Verifying Credentials

Use `CredentialParser` to parse and verify credentials:

```java
import com.pila.credential.vc.CredentialParser;
import com.pila.credential.vc.Credential;
import com.pila.credential.vc.CredentialConfig;

// Optional: Configure DID resolver base URL (defaults to https://auth-dev.pila.vn/api/v1/did)
CredentialConfig.init("https://your-did-resolver.com/api/v1/did");

// Parse credential from JSON bytes
String jsonCredentialString = "{...}"; // Your credential JSON
byte[] rawCredential = jsonCredentialString.getBytes();
Credential credential = CredentialParser.parseCredential(rawCredential);

// Verify the credential (checks proof signature)
credential.verify();

// Access credential contents
byte[] contents = credential.getContents();
System.out.println(new String(contents));
```

The `parseCredential()` method supports:
- JSON credentials (embedded proof format)
- JWT credentials (parsing not yet implemented)

The `verify()` method validates:
- Proof signature using the verification method from the credential
- DID document resolution (if needed)
- Cryptographic proof verification

Notes

- Keys are secp256k1 (compressed pubkey hex, 32-byte privkey hex).
- JWE JSON produced here uses alg ECDH-ES and enc A256GCM (simple format for demo/testing).
- Credential verification requires DID resolver base URL to be configured via `CredentialConfig.init(baseURL)` (defaults to `https://auth-dev.pila.vn/api/v1/did`).
- JSON-LD canonicalization uses RDF Dataset Canonicalization (RDFC) algorithm for deterministic document hashing.
