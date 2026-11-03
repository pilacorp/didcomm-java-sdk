package com.pila.credential.common.sdjwt;

import java.util.List;
import java.util.Map;

public final class BuildDisclosuresInput {
    public Map<String, Object> vc;
    public List<String> selectivePaths;
    public String hashAlgorithm;
    public Boolean shuffle;
    public List<DecoyConfig> decoys;

    public static final class DecoyConfig {
        public String path;
        public int count;
    }
}
