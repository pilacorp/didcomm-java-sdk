package com.pila;

import com.pila.credential.vc.CredentialParser;
import com.pila.didcomm.Decryptor;
import com.pila.didcomm.Encryptor;
import com.pila.didcomm.ecdh.Secp256k1;
import com.pila.credential.vc.Credential;

import java.security.MessageDigest;

public class Main {
    public static void main(String[] args) {
        String message = "{\n" +
                " \"@context\": [\"...\"],\n" +
                " \"id\": \"urn:uuid:...\",\n" +
                " \"type\": [\"VerifiableCredential\"],\n" +
                " \"issuer\": \"did:example:123456\",\n" +
                " \"issuanceDate\": \"...\",\n" +
                " \"credentialSubject\": { \"...\": \"...\" },\n" +
                " \"proof\": {\n" +
                " \"type\": \"Ed25519Signature2020\",\n" +
                " \"created\": \"...\",\n" +
                " \"verificationMethod\": \"did:example:123456#key-1\",\n" +
                " \"proofPurpose\": \"assertionMethod\",\n" +
                " \"jws\": \"...\"\n" +
                " }\n" +
                "}";

        // Sample keys (secp256k1): compressed public key and raw 32-byte private key
        // in
        // hex
        String senderPublicKeyHex = "039c2283702214062a04efb6707db8308ff566c38f93adb93193b175d4f9b354b7";
        String senderPrivateKeyHex = "2c79686425aee8002cb189bf294f2d52ca43851797c7b6e78a7dc361c4373e46";

        try {
            byte[] sharedSecret = Secp256k1.deriveSharedSecret(senderPublicKeyHex,
                    senderPrivateKeyHex);
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(sharedSecret);
            System.out.printf("Recipient derived: %s\n", bytesToHex(digest));

            String jweOutput = Encryptor.encrypt(sharedSecret, message);
            System.out.printf("JWE Output: %s\n", jweOutput);

            String plaintext = Decryptor.decrypt(jweOutput, sharedSecret);
            System.out.printf("Plaintext: %s\n", plaintext);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }

        testCredential();

        System.exit(0);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private static void testCredential() {
        // try to parse credential
        String rawCredential = "{\n" +
                "  \"@context\": [\n" +
                "    \"https://www.w3.org/ns/credentials/v2\",\n" +
                "    \"https://www.w3.org/ns/credentials/examples/v2\"\n" +
                "  ],\n" +
                "  \"credentialSchema\": {\n" +
                "    \"id\": \"https://auth-dev.pila.vn/api/v1/schemas/19cb4f2d-144d-4efd-a3f3-efa007b67d93\",\n" +
                "    \"type\": \"JsonSchema\"\n" +
                "  },\n" +
                "  \"credentialStatus\": {\n" +
                "    \"id\": \"did:nda:testnet:0xf7da5bd53973184ee9f1bebedbd3ab1b0d0d60ee/credentials/status/0#0\",\n" +
                "    \"statusListCredential\": \"https://auth-dev.pila.vn/api/v1/issuers/did:nda:testnet:0xf7da5bd53973184ee9f1bebedbd3ab1b0d0d60ee/credentials/status/0\",\n"
                +
                "    \"statusListIndex\": \"0\",\n" +
                "    \"statusPurpose\": \"revocation\",\n" +
                "    \"type\": \"BitstringStatusListEntry\"\n" +
                "  },\n" +
                "  \"credentialSubject\": {\n" +
                "    \"age\": 10,\n" +
                "    \"department\": \"Engineering\",\n" +
                "    \"id\": \"did:nda:testnet:0x9f57ad527eca94b2ab498549ff961f6bc67909c3\",\n" +
                "    \"name\": \"Test Create\",\n" +
                "    \"salary\": 50000\n" +
                "  },\n" +
                "  \"id\": \"did:nda:testnet:24a22351-daf2-41af-ac98-fa5cbe897e97\",\n" +
                "  \"issuer\": \"did:nda:testnet:0xf7da5bd53973184ee9f1bebedbd3ab1b0d0d60ee\",\n" +
                "  \"proof\": {\n" +
                "    \"created\": \"2025-12-03T03:28:56Z\",\n" +
                "    \"cryptosuite\": \"ecdsa-rdfc-2019\",\n" +
                "    \"proofPurpose\": \"assertionMethod\",\n" +
                "    \"proofValue\": \"ffab9ce2a077a2be721b5999bdbff284bb672e8bafe9b98b87074f2110f6ce127703f6d9941e88b71c35e90fe7e0baf104dc8cba758d2988fa606d4a5761b78c\",\n"
                +
                "    \"type\": \"DataIntegrityProof\",\n" +
                "    \"verificationMethod\": \"did:nda:testnet:0xf7da5bd53973184ee9f1bebedbd3ab1b0d0d60ee#key-1\"\n" +
                "  },\n" +
                "  \"type\": \"VerifiableCredential\",\n" +
                "  \"validFrom\": \"2025-12-03T03:28:56Z\",\n" +
                "  \"validUntil\": \"2026-12-03T03:28:56Z\"\n" +
                "}";

        try {
            Credential credential = CredentialParser.parseCredential(rawCredential.getBytes());

            // print string of credential contents
            byte[] credentialContents = credential.getContents();
            System.out.println(new String(credentialContents));

            // verify credential
            credential.verify();
            System.out.println("---------Verify VC Credential Success---------");
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }

        // parse a jwt vc
        String rawJwt = "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6bmRhOnRlc3RuZXQ6MHg3ZGJkOTkwMTI4MjJmNGNhNGE5YTc0Nzk0YzJhYTk4NTI0MTExYmFlI2tleS0xIiwidHlwIjoiSldUIn0.eyJleHAiOjE3OTYyNjk5MzksImlhdCI6MTc2NDczMzkzOSwiaXNzIjoiZGlkOm5kYTp0ZXN0bmV0OjB4N2RiZDk5MDEyODIyZjRjYTRhOWE3NDc5NGMyYWE5ODUyNDExMWJhZSIsImp0aSI6ImRpZDpuZGE6dGVzdG5ldDpmNjc4YTRlYy0yMDM3LTRiNTgtYjI4Yi04N2UzZTJjOWM2NjMiLCJuYmYiOjE3NjQ3MzM5MzksInN1YiI6ImRpZDpuZGE6dGVzdG5ldDoweDBhMzRiM2E5YTgzNjZkMDczYTEyNzgzOTUxZDMzYzY2ODMzZTUxMTciLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjIiXSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vYXV0aC1kZXYucGlsYS52bi9hcGkvdjEvc2NoZW1hcy9mNGFmYjZiNC1kYjQxLTQ1YzEtOGI5OC02MWUwZjdhOWM3ZGMiLCJ0eXBlIjoiSnNvblNjaGVtYSJ9LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiZGlkOm5kYTp0ZXN0bmV0OjB4N2RiZDk5MDEyODIyZjRjYTRhOWE3NDc5NGMyYWE5ODUyNDExMWJhZS9jcmVkZW50aWFscy9zdGF0dXMvMCMwIiwic3RhdHVzTGlzdENyZWRlbnRpYWwiOiJodHRwczovL2F1dGgtZGV2LnBpbGEudm4vYXBpL3YxL2lzc3VlcnMvZGlkOm5kYTp0ZXN0bmV0OjB4N2RiZDk5MDEyODIyZjRjYTRhOWE3NDc5NGMyYWE5ODUyNDExMWJhZS9jcmVkZW50aWFscy9zdGF0dXMvMCIsInN0YXR1c0xpc3RJbmRleCI6IjAiLCJzdGF0dXNQdXJwb3NlIjoicmV2b2NhdGlvbiIsInR5cGUiOiJCaXRzdHJpbmdTdGF0dXNMaXN0RW50cnkifSwiY3JlZGVudGlhbFN1YmplY3QiOnsiYWdlIjoxMCwiZGVwYXJ0bWVudCI6IkVuZ2luZWVyaW5nIiwiaWQiOiJkaWQ6bmRhOnRlc3RuZXQ6MHgwYTM0YjNhOWE4MzY2ZDA3M2ExMjc4Mzk1MWQzM2M2NjgzM2U1MTE3IiwibmFtZSI6IlRlc3QgQ3JlYXRlIiwic2FsYXJ5Ijo1MDAwMH0sImlkIjoiZGlkOm5kYTp0ZXN0bmV0OmY2NzhhNGVjLTIwMzctNGI1OC1iMjhiLTg3ZTNlMmM5YzY2MyIsImlzc3VlciI6ImRpZDpuZGE6dGVzdG5ldDoweDdkYmQ5OTAxMjgyMmY0Y2E0YTlhNzQ3OTRjMmFhOTg1MjQxMTFiYWUiLCJ0eXBlIjoiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJ2YWxpZEZyb20iOiIyMDI1LTEyLTAzVDAzOjUyOjE5WiIsInZhbGlkVW50aWwiOiIyMDI2LTEyLTAzVDAzOjUyOjE5WiJ9fQ.i2tgKgnDfzC0weOsiY6f531nuxxvQrDmuHG7bBRkR8FgitolK_1L1dMB67FE05ozRi3CSBBpPceliBBQnJ_dcg";

        try {
            Credential credential = CredentialParser.parseCredential(rawJwt.getBytes());

            byte[] credentialContents = credential.getContents();
            System.out.println(new String(credentialContents));
            credential.verify();
            System.out.println("---------Verify VC Credential Success---------");
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
