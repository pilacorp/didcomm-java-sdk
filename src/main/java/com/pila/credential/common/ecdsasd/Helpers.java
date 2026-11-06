package com.pila.credential.common.ecdsasd;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

final class Helpers {

    private Helpers() {
    }

    @SuppressWarnings("unchecked")
    static Object deepCopy(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> out = new HashMap<>();
            for (Map.Entry<?, ?> e : map.entrySet()) {
                out.put(String.valueOf(e.getKey()), deepCopy(e.getValue()));
            }
            return out;
        }
        if (value instanceof List<?> list) {
            List<Object> out = new ArrayList<>(list.size());
            for (Object item : list) {
                out.add(deepCopy(item));
            }
            return out;
        }
        return value;
    }

    static List<Integer> sortedIndexes(Map<Integer, String> matching) {
        List<Integer> out = new ArrayList<>(matching.keySet());
        out.sort(Integer::compareTo);
        return out;
    }

    static List<String> orderedValues(Map<Integer, String> m) {
        List<Integer> idxs = sortedIndexes(m);
        List<String> out = new ArrayList<>(idxs.size());
        for (Integer k : idxs) {
            out.add(m.get(k));
        }
        return out;
    }
}
