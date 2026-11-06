package com.pila.credential.vc;

import com.pila.credential.common.credentialstatus.CredentialStatus;
import com.pila.credential.common.sdjwt.BuildDisclosuresInput;
import com.pila.credential.common.verificationmethod.CredentialResolver;
import lombok.Getter;
import lombok.Setter;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Go {@code CredentialOpt} equivalents shared by every credential type. Each option documents where it is read;
 * an option a call site cannot honour is refused, not silently ignored.
 */
@Getter
@Setter
public class CredentialOptions {
    /** Loads a credential schema JSON by id (Go {@code SchemaLoaderFunc}). */
    @FunctionalInterface
    public interface SchemaLoader {
        byte[] load(String schemaId) throws Exception;
    }

    private boolean validateSchema;
    private boolean verifyProof;
    private boolean checkExpiration;
    private boolean checkRevocation;
    private long clockSkewLeewayMs;
    private String didBaseURL;
    private String verificationMethodKey = "";
    private List<String> sdDisclosures = new ArrayList<>();
    private List<String> sdSelectivePaths = new ArrayList<>();
    private String sdAlg = "";
    private boolean sdShuffle;
    private List<BuildDisclosuresInput.DecoyConfig> sdDecoys = new ArrayList<>();
    private CredentialResolver resolver;
    private String proofVerificationMethod;
    private boolean replaceProof;
    private SchemaLoader schemaLoader;
    private CredentialStatus.Fetcher statusFetcher;

    public CredentialOptions withVerifyProof() {
        this.verifyProof = true;
        return this;
    }

    public CredentialOptions withCheckExpiration() {
        this.checkExpiration = true;
        return this;
    }

    /** Checks the W3C bitstring status list named by {@code credentialStatus} on parse/verify. */
    public CredentialOptions withCheckRevocation() {
        this.checkRevocation = true;
        return this;
    }

    public CredentialOptions withSchemaValidation() {
        this.validateSchema = true;
        return this;
    }

    public CredentialOptions withSchemaLoader(SchemaLoader loader) {
        if (loader != null) {
            this.schemaLoader = loader;
        }
        return this;
    }

    /** Overrides how the status list credential is fetched (default: HTTP GET). */
    public CredentialOptions withStatusFetcher(CredentialStatus.Fetcher fetcher) {
        this.statusFetcher = fetcher;
        return this;
    }

    public CredentialOptions withLeewayMs(long ms) {
        this.clockSkewLeewayMs = Math.max(ms, 0);
        return this;
    }

    public CredentialOptions withLeeway(Duration d) {
        return withLeewayMs(d.toMillis());
    }

    public CredentialOptions withBaseURL(String baseURL) {
        this.didBaseURL = baseURL;
        return this;
    }

    public CredentialOptions withVerificationMethodKey(String key) {
        if (key != null && !key.isEmpty()) {
            this.verificationMethodKey = key;
        }
        return this;
    }

    public CredentialOptions withResolver(CredentialResolver resolver) {
        this.resolver = resolver;
        return this;
    }

    public CredentialOptions withSDSelectivePaths(List<String> paths) {
        this.sdSelectivePaths = paths != null ? paths : new ArrayList<>();
        return this;
    }

    public CredentialOptions withSDDisclosures(List<String> disclosures) {
        this.sdDisclosures = disclosures != null ? disclosures : new ArrayList<>();
        return this;
    }

    public CredentialOptions withSDHashAlgorithm(String alg) {
        this.sdAlg = alg;
        return this;
    }

    public CredentialOptions withSDShuffle(boolean enabled) {
        this.sdShuffle = enabled;
        return this;
    }

    public CredentialOptions withSDDecoyDigests(List<BuildDisclosuresInput.DecoyConfig> decoys) {
        this.sdDecoys = decoys != null ? decoys : new ArrayList<>();
        return this;
    }

    public CredentialOptions withProofVerificationMethod(String vm) {
        this.proofVerificationMethod = vm;
        return this;
    }

    /** JWT/JOSE signing may replace an existing signature; JSON-LD signing refuses this option. */
    public CredentialOptions withReplaceProof() {
        this.replaceProof = true;
        return this;
    }

    /** True when any SD-JWT option is set (Go {@code hasSDOptions}). */
    public boolean hasSDOptions() {
        return (sdDisclosures != null && !sdDisclosures.isEmpty())
                || (sdSelectivePaths != null && !sdSelectivePaths.isEmpty())
                || (sdAlg != null && !sdAlg.isEmpty())
                || sdShuffle
                || (sdDecoys != null && !sdDecoys.isEmpty());
    }

    /** Resolver for this call: injected, else HTTP at {@code withBaseURL}, else the package default. */
    public CredentialResolver effectiveResolver() {
        if (resolver != null) {
            return resolver;
        }
        if (didBaseURL != null && !didBaseURL.isEmpty()) {
            return CredentialConfig.resolverFor(didBaseURL);
        }
        return CredentialConfig.getDocumentResolver();
    }

    /** Copy with proof verification off: there is no signature to verify before signing (Go {@code signingOptions}). */
    public CredentialOptions forSigning() {
        CredentialOptions c = copy();
        c.verifyProof = false;
        return c;
    }

    public CredentialOptions copy() {
        CredentialOptions c = new CredentialOptions();
        c.validateSchema = validateSchema;
        c.verifyProof = verifyProof;
        c.checkExpiration = checkExpiration;
        c.checkRevocation = checkRevocation;
        c.clockSkewLeewayMs = clockSkewLeewayMs;
        c.didBaseURL = didBaseURL;
        c.verificationMethodKey = verificationMethodKey;
        c.sdDisclosures = sdDisclosures;
        c.sdSelectivePaths = sdSelectivePaths;
        c.sdAlg = sdAlg;
        c.sdShuffle = sdShuffle;
        c.sdDecoys = sdDecoys;
        c.resolver = resolver;
        c.proofVerificationMethod = proofVerificationMethod;
        c.replaceProof = replaceProof;
        c.schemaLoader = schemaLoader;
        c.statusFetcher = statusFetcher;
        return c;
    }

    /** Public copy used by presentations to layer their resolver/leeway over the caller's VC options. */
    public CredentialOptions copyForPresentation() {
        return copy();
    }

    public static CredentialOptions orEmpty(CredentialOptions o) {
        return o != null ? o : new CredentialOptions();
    }
}
