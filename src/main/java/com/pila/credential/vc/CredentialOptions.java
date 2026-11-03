package com.pila.credential.vc;

import com.pila.credential.common.sdjwt.BuildDisclosuresInput;
import com.pila.credential.common.verificationmethod.CredentialResolver;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

/**
 * Go {@code CredentialOpt} equivalents used by JOSE / JSON credential paths.
 */
@Getter
@Setter
public class CredentialOptions {
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

    public CredentialOptions withVerifyProof() {
        this.verifyProof = true;
        return this;
    }

    public CredentialOptions withCheckExpiration() {
        this.checkExpiration = true;
        return this;
    }

    public CredentialOptions withCheckRevocation() {
        this.checkRevocation = true;
        return this;
    }

    public CredentialOptions withSchemaValidation() {
        this.validateSchema = true;
        return this;
    }

    public CredentialOptions withLeewayMs(long ms) {
        this.clockSkewLeewayMs = Math.max(ms, 0);
        return this;
    }

    public CredentialOptions withBaseURL(String baseURL) {
        this.didBaseURL = baseURL;
        return this;
    }

    public CredentialOptions withVerificationMethodKey(String key) {
        this.verificationMethodKey = key;
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

    public CredentialOptions withReplaceProof() {
        this.replaceProof = true;
        return this;
    }
}
