package com.pila.credential.common.sdjwt;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public final class SDJWTResult {
    public final Map<String, Object> processedVC;
    public final List<String> disclosures;

    public SDJWTResult(Map<String, Object> processedVC, List<String> disclosures) {
        this.processedVC = processedVC;
        this.disclosures = disclosures != null ? disclosures : new ArrayList<>();
    }
}
