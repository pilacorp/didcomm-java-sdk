package com.pila.credential.common.ecdsasd;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class Disclose {

    public static final class DisclosureData {
        public byte[] baseSignature;
        public byte[] publicKey;
        public List<byte[]> signatures;
        public Map<String, String> labelMap;
        public List<Integer> mandatoryIndexes;
        public Map<String, Object> revealDoc;
    }

    private Disclose() {
    }

    public static DisclosureData createDisclosureData(Map<String, Object> document, String baseProofValue,
            List<String> selectivePointers) throws Exception {
        ProofValue.SpecBaseProof bp = ProofValue.parseBaseProofValue(baseProofValue);

        List<String> combined = new ArrayList<>(bp.mandatoryPointers);
        combined.addAll(selectivePointers);

        Map<String, List<String>> groups = Map.of(
                "mandatory", bp.mandatoryPointers,
                "selective", selectivePointers,
                "combined", combined);

        LabelMap.GroupedCanon grouped = LabelMap.canonicalizeAndGroup(document, bp.hmacKey, groups);
        LabelMap.GroupIndexes mandatoryGroup = grouped.groups.get("mandatory");
        LabelMap.GroupIndexes selectiveGroup = grouped.groups.get("selective");
        LabelMap.GroupIndexes combinedGroup = grouped.groups.get("combined");

        List<Integer> mandatoryIndexes = new ArrayList<>();
        List<Integer> combinedMatching = Helpers.sortedIndexes(combinedGroup.matching);
        for (int rel = 0; rel < combinedMatching.size(); rel++) {
            int abs = combinedMatching.get(rel);
            if (mandatoryGroup.matching.containsKey(abs)) {
                mandatoryIndexes.add(rel);
            }
        }

        List<byte[]> filtered = new ArrayList<>();
        int index = 0;
        for (byte[] sig : bp.signatures) {
            while (mandatoryGroup.matching.containsKey(index)) {
                index++;
            }
            if (selectiveGroup.matching.containsKey(index)) {
                filtered.add(sig);
            }
            index++;
        }

        Map<String, Object> revealDoc = Pointer.selectJsonLd(document, combined);
        if (revealDoc == null) {
            throw new Exception("ecdsasd: no statements to reveal; provide mandatory or selective pointers");
        }

        var canon = com.pila.credential.common.processor.Processor
                .canonicalizeNQuadsWithIdMap(combinedGroup.deskolemizedNQuads);
        Map<String, String> verifierLabelMap = new HashMap<>();
        for (Map.Entry<String, String> e : canon.idMap().entrySet()) {
            String in = stripBnode(e.getKey());
            String verifier = stripBnode(e.getValue());
            String hmac = grouped.labelMap.get(in);
            if (hmac != null) {
                verifierLabelMap.put(verifier, hmac);
            }
        }

        DisclosureData dd = new DisclosureData();
        dd.baseSignature = bp.baseSignature;
        dd.publicKey = bp.publicKey;
        dd.signatures = filtered;
        dd.labelMap = verifierLabelMap;
        dd.mandatoryIndexes = mandatoryIndexes;
        dd.revealDoc = revealDoc;
        return dd;
    }

    private static String stripBnode(String label) {
        return label.startsWith("_:") ? label.substring(2) : label;
    }
}
