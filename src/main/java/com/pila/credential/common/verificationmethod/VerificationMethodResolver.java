package com.pila.credential.common.verificationmethod;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECPoint;

import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Scanner;

/**
 * Resolver for DID verification methods.
 */
public class VerificationMethodResolver implements VerificationMethodResolverProvider {
    private String baseURL;
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final int HTTP_TIMEOUT_MS = 10000;

    public VerificationMethodResolver(String baseURL) {
        this.baseURL = baseURL;
    }

    /**
     * Gets the default public key for an issuer.
     * 
     * @param issuer The issuer DID
     * @return The default public key in hex format (without 0x prefix)
     * @throws Exception if resolution fails
     */
    public String getDefaultPublicKey(String issuer) throws Exception {
        // throw Exception haven't been implemented
        throw new Exception("not implemented");
    }

    /**
     * Gets the public key for a verification method.
     * 
     * @param verificationMethodURL The verification method URL (e.g.,
     *                              "did:example:123#key-1")
     * @return The public key in hex format (without 0x prefix)
     * @throws Exception if resolution fails
     */
    public String getPublicKey(String verificationMethodURL) throws Exception {
        // Extract DID from verification method URL
        String didPart;
        int hashIndex = verificationMethodURL.indexOf('#');
        if (hashIndex > 0) {
            didPart = verificationMethodURL.substring(0, hashIndex);
        } else {
            throw new Exception("invalid verification method URL, could not extract DID: " + verificationMethodURL);
        }

        if (didPart.isEmpty()) {
            throw new Exception("invalid verification method URL, could not extract DID: " + verificationMethodURL);
        }

        // Resolve DID document
        DIDDocument doc = resolveToDoc(didPart);

        // Find matching verification method
        if (doc.getVerificationMethod() != null) {
            for (VerificationMethodEntry vm : doc.getVerificationMethod()) {
                if (verificationMethodURL.equals(vm.getId())) {
                    // Format publicKeyHex
                    if (vm.getPublicKeyHex() != null && !vm.getPublicKeyHex().isEmpty()) {
                        String publicKey = vm.getPublicKeyHex();
                        if (publicKey.startsWith("0x")) {
                            publicKey = publicKey.substring(2);
                        }
                        return publicKey;
                    }

                    // Format publicKeyJwk
                    if (vm.getPublicKeyJwk() != null) {
                        String hexKey = jwkToHex(vm.getPublicKeyJwk());
                        return hexKey;
                    }

                    throw new Exception("no public key found in verification method '" + verificationMethodURL + "'");
                }
            }
        }

        throw new Exception("verification method '" + verificationMethodURL + "' not found in DID document");
    }

    /**
     * Converts a JWK to hex format for secp256k1 keys.
     */
    private String jwkToHex(JWK jwk) throws Exception {
        if (!"EC".equals(jwk.getKty())) {
            throw new Exception("unsupported key type: " + jwk.getKty());
        }

        if (!"secp256k1".equals(jwk.getCrv())) {
            throw new Exception("unsupported curve: " + jwk.getCrv());
        }

        // Decode base64url encoded coordinates
        byte[] xBytes;
        byte[] yBytes;
        try {
            xBytes = Base64.getUrlDecoder().decode(jwk.getX());
            yBytes = Base64.getUrlDecoder().decode(jwk.getY());
        } catch (Exception e) {
            throw new Exception("failed to decode JWK coordinates: " + e.getMessage(), e);
        }

        // Convert to big integers
        BigInteger x = new BigInteger(1, xBytes);
        BigInteger y = new BigInteger(1, yBytes);

        // Get secp256k1 curve parameters
        X9ECParameters ecParams = CustomNamedCurves.getByName("secp256k1");
        if (ecParams == null) {
            throw new Exception("secp256k1 curve not found");
        }

        // Create ECDSA public key point
        ECPoint point = ecParams.getCurve().createPoint(x, y);

        // Convert to uncompressed format (0x04 + x + y)
        byte[] uncompressed = point.getEncoded(false); // false = uncompressed

        // Return as hex string
        StringBuilder hex = new StringBuilder(uncompressed.length * 2);
        for (byte b : uncompressed) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    /**
     * Fetches and parses a DID document from the resolver endpoint.
     */
    private DIDDocument resolveToDoc(String did) throws Exception {
        // Construct and encode API URL
        String encodedDID = URLEncoder.encode(did, StandardCharsets.UTF_8.toString());
        String apiURL = baseURL + "/" + encodedDID;

        // Perform HTTP GET request
        URI uri = new URI(apiURL);
        HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(HTTP_TIMEOUT_MS);
        conn.setReadTimeout(HTTP_TIMEOUT_MS);

        int responseCode = conn.getResponseCode();
        if (responseCode != HttpURLConnection.HTTP_OK) {
            throw new Exception("DID resolver API returned non-200 status: " + responseCode);
        }

        // Read response
        String body;
        try (InputStream inputStream = conn.getInputStream();
                Scanner scanner = new Scanner(inputStream, StandardCharsets.UTF_8.toString()).useDelimiter("\\A")) {
            body = scanner.hasNext() ? scanner.next() : "";
        }

        // Parse JSON
        try {
            return objectMapper.readValue(body, DIDDocument.class);
        } catch (Exception e) {
            throw new Exception("failed to unmarshal DID document JSON: " + e.getMessage(), e);
        }
    }

    /**
     * Checks if the private key and verification method match.
     * 
     * @param privateKey         The private key in hex format
     * @param verificationMethod The verification method URL
     * @return true if the private key and verification method match, false
     *         otherwise
     * @throws Exception if the check fails
     */
    public boolean checkVerificationMethod(String privateKey, String verificationMethod) throws Exception {
        // throw Exception haven't been implemented
        throw new Exception("not implemented");
    }
}
