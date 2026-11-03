package com.pila.credential.common.verificationmethod;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;

import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.Security;
import java.util.Base64;
import java.util.Scanner;

/**
 * Resolver for DID verification methods.
 */
public class VerificationMethodResolver implements DocumentResolver {
    private String baseURL;
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final int HTTP_TIMEOUT_MS = 10000;

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

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
        if (issuer == null || issuer.isEmpty()) {
            throw new Exception("issuer is required");
        }
        if (issuer.indexOf('#') > 0) {
            return getPublicKey(issuer);
        }

        DIDDocument doc = resolveToDoc(issuer);

        // Prefer the DID's authentication method, then fall back to the first
        // verification method in the document.
        if (doc.getAuthentication() != null) {
            for (String vmId : doc.getAuthentication()) {
                if (vmId != null && !vmId.isEmpty()) {
                    return getPublicKey(vmId);
                }
            }
        }

        if (doc.getVerificationMethod() != null && !doc.getVerificationMethod().isEmpty()) {
            VerificationMethodEntry vm = doc.getVerificationMethod().get(0);
            if (vm.getPublicKeyHex() != null && !vm.getPublicKeyHex().isEmpty()) {
                String publicKey = vm.getPublicKeyHex();
                return publicKey.startsWith("0x") ? publicKey.substring(2) : publicKey;
            }
            if (vm.getPublicKeyJwk() != null) {
                return jwkToHex(vm.getPublicKeyJwk());
            }
        }

        throw new Exception("no public key found for DID '" + issuer + "'");
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
     * Returns the verification method entry for a DID URL fragment.
     */
    public VerificationMethodEntry findVerificationMethod(String verificationMethodURL) throws Exception {
        String didPart;
        int hashIndex = verificationMethodURL.indexOf('#');
        if (hashIndex > 0) {
            didPart = verificationMethodURL.substring(0, hashIndex);
        } else {
            throw new Exception("invalid verification method URL: " + verificationMethodURL);
        }
        DIDDocument doc = resolveToDoc(didPart);
        if (doc.getVerificationMethod() != null) {
            for (VerificationMethodEntry vm : doc.getVerificationMethod()) {
                if (verificationMethodURL.equals(vm.getId())) {
                    return vm;
                }
            }
        }
        throw new Exception("verification method '" + verificationMethodURL + "' not found in DID document");
    }

    /**
     * Resolves the assertionMethod verification method for signing (key-1 by default).
     */
    public VerificationMethodEntry resolveAssertionMethod(String issuerDid, String verificationMethodKey)
            throws Exception {
        DIDDocument doc = resolveToDoc(issuerDid);
        String fragment = (verificationMethodKey == null || verificationMethodKey.isBlank()) ? "key-1"
                : verificationMethodKey;
        String target = issuerDid + "#" + fragment;
        if (doc.getVerificationMethod() != null) {
            for (VerificationMethodEntry vm : doc.getVerificationMethod()) {
                if (target.equals(vm.getId())) {
                    return vm;
                }
            }
        }
        throw new Exception("verification method '" + target + "' not found for issuer " + issuerDid);
    }

    /**
     * Builds a BouncyCastle EC public key from a verification method entry.
     */
    public java.security.PublicKey ecPublicKeyFromEntry(VerificationMethodEntry vm) throws Exception {
        if (vm.getPublicKeyJwk() != null) {
            return jwkToPublicKey(vm.getPublicKeyJwk());
        }
        if (vm.getPublicKeyMultibase() != null && !vm.getPublicKeyMultibase().isEmpty()) {
            return Multikey.publicKeyFromMultibase(vm.getPublicKeyMultibase());
        }
        if (vm.getPublicKeyHex() != null && !vm.getPublicKeyHex().isEmpty()) {
            if (VerificationMethodKeyKind.fromEntry(vm) != VerificationMethodKeyKind.SECP256K1) {
                throw new Exception("publicKeyHex is only valid for secp256k1 verification methods, got type "
                        + vm.getType());
            }
            String hex = vm.getPublicKeyHex().startsWith("0x") ? vm.getPublicKeyHex().substring(2)
                    : vm.getPublicKeyHex();
            byte[] pubBytes = hexStringToBytes(hex);
            X9ECParameters ecParams = CustomNamedCurves.getByName("secp256k1");
            ECPoint point = ecParams.getCurve().decodePoint(pubBytes);
            KeyFactory kf = KeyFactory.getInstance("EC", "BC");
            return kf.generatePublic(new org.bouncycastle.jce.spec.ECPublicKeySpec(point,
                    ECNamedCurveTable.getParameterSpec("secp256k1")));
        }
        throw new Exception("no public key in verification method " + vm.getId());
    }

    private java.security.PublicKey jwkToPublicKey(JWK jwk) throws Exception {
        if (!"EC".equals(jwk.getKty())) {
            throw new Exception("unsupported key type: " + jwk.getKty());
        }
        byte[] xBytes = Base64.getUrlDecoder().decode(jwk.getX());
        byte[] yBytes = Base64.getUrlDecoder().decode(jwk.getY());
        BigInteger x = new BigInteger(1, xBytes);
        BigInteger y = new BigInteger(1, yBytes);

        String curveName;
        if ("secp256k1".equals(jwk.getCrv())) {
            curveName = "secp256k1";
        } else if ("P-256".equals(jwk.getCrv())) {
            curveName = "prime256v1";
        } else {
            throw new Exception("unsupported curve: " + jwk.getCrv());
        }

        X9ECParameters ecParams = CustomNamedCurves.getByName(curveName);
        if (ecParams == null && "P-256".equals(jwk.getCrv())) {
            ecParams = CustomNamedCurves.getByName("P-256");
        }
        if (ecParams == null) {
            throw new Exception("curve not found: " + jwk.getCrv());
        }
        ECPoint point = ecParams.getCurve().createPoint(x, y);
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        return kf.generatePublic(new org.bouncycastle.jce.spec.ECPublicKeySpec(point,
                ECNamedCurveTable.getParameterSpec(curveName)));
    }

    private static byte[] hexStringToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
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
     * Resolves a DID to its document (for verification and strict-purpose checks).
     */
    public DIDDocument resolveDocument(String did) throws Exception {
        return resolveToDoc(did);
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
