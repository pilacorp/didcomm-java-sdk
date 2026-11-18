package com.pila.credential.digitalcredential.didresolver;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.pila.credential.common.util.Rfc3339;

/**
 * Resolves the signing keys of an issuer whose {@code iss} is a DID (port of Go
 * {@code digitalcredential/didresolver}; W3C DID Resolution v1.0, Controlled Identifiers v1.0).
 *
 * <p>Only the verification methods listed in {@code assertionMethod} count, each belonging to this document
 * and accepted by {@link #defaultAcceptKey} or the caller's {@link AcceptKey}. Every {@link #keys} makes one
 * resolution: nothing is cached, so a revocation is seen on the next call.
 */
public final class DidResolver {
    /** One published key: its kid (absolute verification method URL) and the key. */
    public record IssuerKey(String kid, PublicKey key) {
    }

    /** DID resolution over any transport; returns a resolution result or a DID document alone, as JSON. */
    @FunctionalInterface
    public interface Transport {
        byte[] resolve(String did) throws Exception;
    }

    /** What a DID document says about a verification method; zero times are {@code null}. */
    public record KeyInfo(String id, Instant revoked, Instant expires, String revocationReason, Instant at) {
    }

    @FunctionalInterface
    public interface AcceptKey {
        boolean accept(KeyInfo k);
    }

    /** iss is not accepted at all (not a DID, or the resolver refuses the DID or its method). */
    public static class IssuerNotSupportedException extends Exception {
        public IssuerNotSupportedException(String m) {
            super(m);
        }
    }

    /** The resolver answered, and the answer gives no usable key (not found, deactivated, invalid document). */
    public static class NoUsableKeyException extends Exception {
        public NoUsableKeyException(String m) {
            super(m);
        }
    }

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private static final String DID_NS = "https://www.w3.org/ns/did#";
    private static final String KEY_COMPROMISE = "keyCompromise";
    private static final Instant ZERO_TIME = Instant.parse("0001-01-01T00:00:00Z");
    private static final Map<String, Integer> STATUS_OF = Map.of(
            "INVALID_DID", 400, "INVALID_DID_URL", 400, "INVALID_OPTIONS", 400, "NOT_FOUND", 404,
            "REPRESENTATION_NOT_SUPPORTED", 406, "INVALID_DID_DOCUMENT", 500, "METHOD_NOT_SUPPORTED", 501,
            "FEATURE_NOT_SUPPORTED", 501, "INTERNAL_ERROR", 500);

    private final Transport transport;
    private final AcceptKey accept;

    /** @param transport how DIDs are resolved, e.g. {@link HttpTransport}; @param accept null = default rule. */
    public DidResolver(Transport transport, AcceptKey accept) {
        if (transport == null) {
            throw new IllegalArgumentException("didresolver: transport is required");
        }
        this.transport = transport;
        this.accept = accept != null ? accept : DidResolver::defaultAcceptKey;
    }

    /**
     * W3C CID rule with one exception: a key verifies until its revoked or expires time, but a key revoked for
     * a stated reason other than keyCompromise verifies until it expires (its issuer retired it, did not lose
     * it). A key revoked as keyCompromise, or with no reason, fails for every token.
     */
    public static boolean defaultAcceptKey(KeyInfo k) {
        if (k.expires() != null && !k.at().isBefore(k.expires())) {
            return false;
        }
        if (k.revoked() == null || k.at().isBefore(k.revoked())) {
            return true;
        }
        return k.revocationReason() != null && !k.revocationReason().isEmpty()
                && !KEY_COMPROMISE.equals(k.revocationReason());
    }

    /** The keys the DID document of {@code iss} lists under assertionMethod, possibly none. */
    public List<IssuerKey> keys(String iss) throws Exception {
        return keys(iss, Instant.now());
    }

    List<IssuerKey> keys(String iss, Instant now) throws Exception {
        if (iss == null || iss.isEmpty()) {
            throw new IssuerNotSupportedException("didresolver: credential has no iss");
        }
        if (!iss.startsWith("did:")) {
            throw new IssuerNotSupportedException("didresolver: iss is not a DID; use issuermeta for an https iss");
        }
        if (!conformantDid(iss)) {
            throw new IssuerNotSupportedException("didresolver: iss is not a valid DID");
        }
        Map<String, Object> doc = parseResolution(transport.resolve(iss), iss);
        return assertionKeys(doc, iss, now);
    }

    /** DID Core 1.0 §3.1; leaves no "/", "?" or "#", so a DID stays one path segment of a request URL. */
    static boolean conformantDid(String s) {
        String rest = s.substring(4);
        int c = rest.indexOf(':');
        if (c <= 0 || c == rest.length() - 1 || rest.charAt(rest.length() - 1) == ':') {
            return false;
        }
        String method = rest.substring(0, c);
        String id = rest.substring(c + 1);
        for (int i = 0; i < method.length(); i++) {
            char m = method.charAt(i);
            if ((m < 'a' || m > 'z') && (m < '0' || m > '9')) {
                return false;
            }
        }
        for (int i = 0; i < id.length(); i++) {
            char ch = id.charAt(i);
            if (isAlnum(ch) || ch == '.' || ch == '-' || ch == '_' || ch == ':') {
                continue;
            }
            if (ch == '%' && i + 2 < id.length() && isHex(id.charAt(i + 1)) && isHex(id.charAt(i + 2))) {
                i += 2;
                continue;
            }
            return false;
        }
        return true;
    }

    private static boolean isAlnum(char c) {
        return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9';
    }

    private static boolean isHex(char c) {
        return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F';
    }

    private static NoUsableKeyException fault(String m) {
        return new NoUsableKeyException("didresolver: " + m);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object o) {
        return o instanceof Map ? (Map<String, Object>) o : null;
    }

    /** A resolution result or a DID document alone (told by its didDocument member), whose id must equal did. */
    static Map<String, Object> parseResolution(byte[] body, String did) throws Exception {
        Map<String, Object> top;
        try {
            top = MAPPER.readValue(body, new TypeReference<LinkedHashMap<String, Object>>() {
            });
        } catch (Exception e) {
            throw fault("invalid resolver response: not a valid JSON object"); // no cause: it may quote the body
        }
        if (top == null) {
            throw fault("invalid resolver response: not a valid JSON object");
        }
        Map<String, Object> docMeta = asMap(top.get("didDocumentMetadata"));
        if (docMeta != null && Boolean.TRUE.equals(docMeta.get("deactivated"))) {
            throw answer(410, "");
        }
        Map<String, Object> resMeta = asMap(top.get("didResolutionMetadata"));
        if (resMeta != null && resMeta.get("error") != null) {
            throw resolutionError(resMeta.get("error"));
        }
        Map<String, Object> doc = top;
        if (top.containsKey("didDocument")) {
            doc = asMap(top.get("didDocument"));
            if (doc == null) {
                throw fault("invalid resolver response: no DID document");
            }
        }
        if (!did.equals(doc.get("id"))) {
            throw fault("invalid DID document: id does not match the DID");
        }
        return doc;
    }

    /** The outcome DID Resolution §9.1 gives a status: 400/501 refuse, 404/410 no key; otherwise null. */
    static Exception answer(int status, String said) {
        return switch (status) {
            case 400, 501 -> new IssuerNotSupportedException("didresolver: resolver refused this DID (" + said + ")");
            case 404 -> fault("DID not found");
            case 410 -> fault("DID is deactivated");
            default -> null;
        };
    }

    private static Exception resolutionError(Object e) {
        Map<String, Object> obj = asMap(e);
        Object typ = obj == null ? null : obj.get("type");
        String name = typ instanceof String t && t.startsWith(DID_NS) ? t.substring(DID_NS.length()) : null;
        Integer status = name == null ? null : STATUS_OF.get(name);
        if (status == null) {
            return new Exception("didresolver: resolver returned an unknown error");
        }
        Exception a = answer(status, name);
        return a != null ? a : new Exception("didresolver: resolver returned " + name);
    }

    private List<IssuerKey> assertionKeys(Map<String, Object> doc, String did, Instant now) throws Exception {
        Map<String, Map<String, Object>> methods = methodsById(doc, did);
        List<IssuerKey> keys = new ArrayList<>();
        if (!doc.containsKey("assertionMethod")) {
            return keys;
        }
        if (!(doc.get("assertionMethod") instanceof List<?> refs)) {
            throw fault("invalid DID document: assertionMethod is not an array");
        }
        Map<String, Map<String, Object>> seen = new HashMap<>();
        for (Object ref : refs) {
            String id;
            Map<String, Object> vm;
            if (ref instanceof String s) {
                id = absoluteId(s, did);
                vm = methods.get(id);
            } else if (ref instanceof Map<?, ?>) {
                vm = asMap(ref);
                id = absoluteId(vm.get("id") instanceof String s ? s : "", did);
            } else {
                throw fault("invalid DID document: assertionMethod has an entry that is neither a string nor an object");
            }
            if (vm == null) {
                continue;
            }
            boolean judged = seen.containsKey(id);
            define(seen, id, vm);
            if (judged || !belongs(vm, id, did)) {
                continue;
            }
            PublicKey pub = DidKeys.publicKey(vm);
            if (pub == null) {
                continue;
            }
            KeyInfo info = keyInfo(vm, id, now);
            if (info != null && accept.accept(info)) {
                keys.add(new IssuerKey(id, pub));
            }
        }
        return keys;
    }

    private static Map<String, Map<String, Object>> methodsById(Map<String, Object> doc, String did) throws Exception {
        Map<String, Map<String, Object>> methods = new HashMap<>();
        if (!doc.containsKey("verificationMethod")) {
            return methods;
        }
        if (!(doc.get("verificationMethod") instanceof List<?> list)) {
            throw fault("invalid DID document: verificationMethod is not an array");
        }
        for (Object e : list) {
            Map<String, Object> vm = asMap(e);
            if (vm == null) {
                throw fault("invalid DID document: verificationMethod has an entry that is not an object");
            }
            define(methods, absoluteId(vm.get("id") instanceof String s ? s : "", did), vm);
        }
        return methods;
    }

    /** Two different definitions of one id leave a reference with no single meaning: refuse the document. */
    private static void define(Map<String, Map<String, Object>> methods, String id, Map<String, Object> vm)
            throws Exception {
        Map<String, Object> prev = methods.get(id);
        if (prev != null && !id.isEmpty() && !prev.equals(vm)) {
            throw fault("invalid DID document: two keys have the same id");
        }
        methods.put(id, vm);
    }

    private static String absoluteId(String id, String did) {
        return id.startsWith("#") ? did + id : id;
    }

    /** CID §3.3: the method lives in this document and names it as controller. */
    private static boolean belongs(Map<String, Object> vm, String id, String did) {
        return id.startsWith(did + "#") && id.length() > did.length() + 1 && did.equals(vm.get("controller"));
    }

    /** null when a revoked/expires time is unreadable (the key is dropped before any AcceptKey sees it). */
    private static KeyInfo keyInfo(Map<String, Object> vm, String id, Instant now) {
        Instant[] t = new Instant[2];
        String[] names = {"revoked", "expires"};
        for (int i = 0; i < 2; i++) {
            if (!vm.containsKey(names[i])) {
                continue;
            }
            try {
                Instant at = Rfc3339.parse(vm.get(names[i]) instanceof String s ? s : "");
                if (at.equals(ZERO_TIME)) {
                    return null;
                }
                t[i] = at;
            } catch (RuntimeException e) {
                return null;
            }
        }
        String reason = vm.get("revocationReason") instanceof String s ? s : "";
        return new KeyInfo(id, t[0], t[1], reason, now);
    }
}
