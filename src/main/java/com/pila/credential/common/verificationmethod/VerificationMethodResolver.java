package com.pila.credential.common.verificationmethod;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

/**
 * HTTP-backed DID document resolver.
 */
public class VerificationMethodResolver implements CredentialResolver {
    private final String baseURL;
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final int HTTP_TIMEOUT_MS = 10000;

    public VerificationMethodResolver(String baseURL) {
        this.baseURL = baseURL;
    }

    public String getDefaultPublicKey(String issuer) throws Exception {
        return getDefaultPublicKeyHex(issuer);
    }

    public String getPublicKey(String verificationMethodURL) throws Exception {
        return VerificationMethodMaterial.getPublicKeyHex(this, verificationMethodURL);
    }

    public VerificationMethodEntry resolveAssertionMethod(String issuerDid, String verificationMethodKey)
            throws Exception {
        DIDDocument doc = resolveDocument(issuerDid);
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

    @Override
    public DIDDocument resolveDocument(String did) throws Exception {
        String encodedDID = URLEncoder.encode(did, StandardCharsets.UTF_8);
        String apiURL = baseURL + "/" + encodedDID;

        URI uri = new URI(apiURL);
        String scheme = uri.getScheme();
        if (scheme == null || (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme))) {
            throw new Exception("DID resolver URL must use http or https: " + apiURL);
        }
        if (uri.getHost() == null || uri.getHost().isEmpty()) {
            throw new Exception("DID resolver URL must include a host: " + apiURL);
        }

        HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(HTTP_TIMEOUT_MS);
        conn.setReadTimeout(HTTP_TIMEOUT_MS);

        int responseCode = conn.getResponseCode();
        if (responseCode != HttpURLConnection.HTTP_OK) {
            throw new Exception("DID resolver API returned non-200 status: " + responseCode);
        }

        String body;
        try (InputStream inputStream = conn.getInputStream();
                Scanner scanner = new Scanner(inputStream, StandardCharsets.UTF_8).useDelimiter("\\A")) {
            body = scanner.hasNext() ? scanner.next() : "";
        }

        try {
            return objectMapper.readValue(body, DIDDocument.class);
        } catch (Exception e) {
            throw new Exception("failed to unmarshal DID document JSON: " + e.getMessage(), e);
        }
    }

    public boolean checkVerificationMethod(String privateKey, String verificationMethod) throws Exception {
        throw new Exception("not implemented");
    }
}
