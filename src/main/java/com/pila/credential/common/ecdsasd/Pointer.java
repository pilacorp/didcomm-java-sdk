package com.pila.credential.common.ecdsasd;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class Pointer {

    private Pointer() {
    }

    public static List<Object> parsePointer(String pointer) {
        String[] parts = pointer.split("/", -1);
        if (parts.length > 0 && parts[0].isEmpty()) {
            parts = java.util.Arrays.copyOfRange(parts, 1, parts.length);
        }
        List<Object> parsed = new ArrayList<>(parts.length);
        for (String part : parts) {
            if (part.isEmpty()) {
                continue;
            }
            if (!part.contains("~")) {
                try {
                    parsed.add(Integer.parseInt(part));
                    continue;
                } catch (NumberFormatException ignored) {
                    parsed.add(part);
                    continue;
                }
            }
            String un = part.replace("~1", "/").replace("~0", "~");
            parsed.add(un);
        }
        return parsed;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> selectJsonLd(Map<String, Object> document, List<String> pointers)
            throws Exception {
        if (pointers == null || pointers.isEmpty()) {
            return null;
        }
        Map<String, Object> sel = new HashMap<>();
        if (document.containsKey("@context")) {
            sel.put("@context", Helpers.deepCopy(document.get("@context")));
        }
        initSelection(sel, document);

        for (String pointer : pointers) {
            List<Object> paths = parsePointer(pointer);
            if (paths.isEmpty()) {
                return (Map<String, Object>) Helpers.deepCopy(document);
            }
            Object updated = selectInto(document, paths, sel);
            if (updated instanceof Map<?, ?> m) {
                sel = (Map<String, Object>) m;
            }
        }
        densifyArrays(sel);
        return sel;
    }

    @SuppressWarnings("unchecked")
    private static Object selectInto(Object source, List<Object> paths, Object sel) throws Exception {
        if (paths.isEmpty()) {
            if (source instanceof Map<?, ?> v) {
                Map<String, Object> merged = new HashMap<>();
                if (sel instanceof Map<?, ?> sm) {
                    for (Map.Entry<?, ?> e : sm.entrySet()) {
                        merged.put(String.valueOf(e.getKey()), e.getValue());
                    }
                }
                for (Map.Entry<?, ?> e : v.entrySet()) {
                    merged.put(String.valueOf(e.getKey()), Helpers.deepCopy(e.getValue()));
                }
                return merged;
            }
            if (source instanceof List<?> v) {
                return Helpers.deepCopy(v);
            }
            return source;
        }

        Object path = paths.get(0);
        List<Object> rest = paths.subList(1, paths.size());
        Object childSource = getChild(source, path);
        if (childSource == null) {
            throw new Exception("JSON pointer does not match document");
        }

        Object childSel = getChild(sel, path);
        if (childSel == null) {
            if (childSource instanceof List<?>) {
                childSel = new ArrayList<>();
            } else {
                childSel = initSelection(new HashMap<>(), childSource);
            }
        }

        Object newChild = selectInto(childSource, rest, childSel);
        return setChild(sel, path, newChild);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> initSelection(Map<String, Object> sel, Object source) {
        if (!(source instanceof Map<?, ?> m)) {
            return sel;
        }
        Object id = m.get("id");
        if (id instanceof String s && !s.startsWith("_:")) {
            sel.put("id", id);
        }
        if (m.containsKey("type")) {
            sel.put("type", m.get("type"));
        }
        return sel;
    }

    @SuppressWarnings("unchecked")
    private static Object getChild(Object parent, Object path) {
        if (parent instanceof Map<?, ?> map) {
            if (!(path instanceof String key)) {
                return null;
            }
            return map.get(key);
        }
        if (parent instanceof List<?> list) {
            if (!(path instanceof Integer idx) || idx < 0 || idx >= list.size()) {
                return null;
            }
            return list.get(idx);
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static Object setChild(Object parent, Object path, Object val) {
        if (parent instanceof Map<?, ?> map && path instanceof String key) {
            ((Map<String, Object>) map).put(key, val);
            return parent;
        }
        if (parent instanceof List<?> list && path instanceof Integer idx) {
            List<Object> mut = (List<Object>) list;
            while (mut.size() <= idx) {
                mut.add(null);
            }
            mut.set(idx, val);
            return parent;
        }
        return parent;
    }

    @SuppressWarnings("unchecked")
    private static void densifyArrays(Object v) {
        if (v instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> e : map.entrySet()) {
                densifyArrays(e.getValue());
            }
            return;
        }
        if (v instanceof List<?> list) {
            List<Object> out = new ArrayList<>();
            for (Object e : list) {
                if (e == null) {
                    continue;
                }
                densifyArrays(e);
                out.add(e);
            }
            ((List<Object>) list).clear();
            ((List<Object>) list).addAll(out);
        }
    }
}
