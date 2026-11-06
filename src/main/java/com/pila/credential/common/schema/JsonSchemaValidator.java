package com.pila.credential.common.schema;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Pattern;

/**
 * JSON Schema draft-07 core validator (no JSON-schema library is available offline, and Go uses
 * gojsonschema). Supports type, enum, const, properties, required, additionalProperties, patternProperties,
 * items, additionalItems, min/maxItems, uniqueItems, min/maxLength, pattern, minimum/maximum (+exclusive),
 * multipleOf, min/maxProperties, allOf/anyOf/oneOf/not, if/then/else and local {@code $ref}
 * ({@code #}, {@code #/definitions/...}). Not supported and refused rather than ignored: remote {@code $ref}.
 * {@code format} is annotation-only, as in draft-07.
 */
public final class JsonSchemaValidator {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final JsonNode root;
    private final List<String> errors = new ArrayList<>();

    private JsonSchemaValidator(JsonNode root) {
        this.root = root;
    }

    /** Returns the list of violations (empty when the instance is valid). */
    public static List<String> validate(byte[] schemaJson, Object instance) throws Exception {
        JsonNode schema = MAPPER.readTree(schemaJson);
        JsonNode inst = MAPPER.valueToTree(instance);
        JsonSchemaValidator v = new JsonSchemaValidator(schema);
        v.check(schema, inst, "(root)", 0);
        return v.errors;
    }

    private boolean check(JsonNode schema, JsonNode inst, String path, int depth) throws Exception {
        int before = errors.size();
        if (depth > 64) {
            throw new Exception("schema nesting too deep");
        }
        if (schema.isBoolean()) {
            if (!schema.booleanValue()) {
                errors.add(path + ": schema is false");
            }
            return errors.size() == before;
        }
        if (!schema.isObject()) {
            throw new Exception("invalid schema at " + path);
        }
        if (schema.has("$ref")) {
            String ref = schema.get("$ref").asText();
            if (!ref.startsWith("#")) {
                throw new Exception("unsupported remote $ref " + ref);
            }
            JsonNode target = ref.equals("#") ? root : root.at(ref.substring(1));
            if (target.isMissingNode()) {
                throw new Exception("unresolvable $ref " + ref);
            }
            return check(target, inst, path, depth + 1);
        }
        if (schema.has("type") && !typeMatches(schema.get("type"), inst)) {
            errors.add(path + ": invalid type, expected " + schema.get("type"));
            return false;
        }
        if (schema.has("enum")) {
            boolean ok = false;
            for (JsonNode e : schema.get("enum")) {
                ok |= e.equals(inst);
            }
            if (!ok) {
                errors.add(path + ": must be one of " + schema.get("enum"));
            }
        }
        if (schema.has("const") && !schema.get("const").equals(inst)) {
            errors.add(path + ": must equal " + schema.get("const"));
        }
        if (inst.isObject()) {
            checkObject(schema, inst, path, depth);
        }
        if (inst.isArray()) {
            checkArray(schema, inst, path, depth);
        }
        if (inst.isTextual()) {
            String s = inst.asText();
            int len = s.codePointCount(0, s.length());
            if (schema.has("minLength") && len < schema.get("minLength").asInt()) {
                errors.add(path + ": string length must be >= " + schema.get("minLength"));
            }
            if (schema.has("maxLength") && len > schema.get("maxLength").asInt()) {
                errors.add(path + ": string length must be <= " + schema.get("maxLength"));
            }
            if (schema.has("pattern") && !Pattern.compile(schema.get("pattern").asText()).matcher(s).find()) {
                errors.add(path + ": does not match pattern " + schema.get("pattern").asText());
            }
        }
        if (inst.isNumber()) {
            BigDecimal n = inst.decimalValue();
            cmp(schema, "minimum", n, path, c -> c < 0, ">=");
            cmp(schema, "maximum", n, path, c -> c > 0, "<=");
            cmp(schema, "exclusiveMinimum", n, path, c -> c <= 0, ">");
            cmp(schema, "exclusiveMaximum", n, path, c -> c >= 0, "<");
            if (schema.has("multipleOf")) {
                BigDecimal m = schema.get("multipleOf").decimalValue();
                if (m.signum() > 0 && n.remainder(m).signum() != 0) {
                    errors.add(path + ": must be a multiple of " + m);
                }
            }
        }
        if (schema.has("allOf")) {
            for (JsonNode s : schema.get("allOf")) {
                check(s, inst, path, depth + 1);
            }
        }
        if (schema.has("anyOf")) {
            boolean any = false;
            for (JsonNode s : schema.get("anyOf")) {
                any |= sub(s, inst, path, depth);
            }
            if (!any) {
                errors.add(path + ": must match at least one schema in anyOf");
            }
        }
        if (schema.has("oneOf")) {
            int n = 0;
            for (JsonNode s : schema.get("oneOf")) {
                if (sub(s, inst, path, depth)) {
                    n++;
                }
            }
            if (n != 1) {
                errors.add(path + ": must match exactly one schema in oneOf, matched " + n);
            }
        }
        if (schema.has("not") && sub(schema.get("not"), inst, path, depth)) {
            errors.add(path + ": must not match the schema in not");
        }
        if (schema.has("if")) {
            if (sub(schema.get("if"), inst, path, depth)) {
                if (schema.has("then")) {
                    check(schema.get("then"), inst, path, depth + 1);
                }
            } else if (schema.has("else")) {
                check(schema.get("else"), inst, path, depth + 1);
            }
        }
        return errors.size() == before;
    }

    private boolean sub(JsonNode s, JsonNode inst, String path, int depth) throws Exception {
        int mark = errors.size();
        boolean ok = check(s, inst, path, depth + 1);
        while (errors.size() > mark) {
            errors.remove(errors.size() - 1);
        }
        return ok;
    }

    private interface Cmp {
        boolean bad(int c);
    }

    private void cmp(JsonNode schema, String kw, BigDecimal n, String path, Cmp bad, String op) {
        if (schema.has(kw) && schema.get(kw).isNumber() && bad.bad(n.compareTo(schema.get(kw).decimalValue()))) {
            errors.add(path + ": must be " + op + " " + schema.get(kw));
        }
    }

    private void checkObject(JsonNode schema, JsonNode inst, String path, int depth) throws Exception {
        if (schema.has("required")) {
            for (JsonNode r : schema.get("required")) {
                if (!inst.has(r.asText())) {
                    errors.add(path + ": " + r.asText() + " is required");
                }
            }
        }
        if (schema.has("minProperties") && inst.size() < schema.get("minProperties").asInt()) {
            errors.add(path + ": must have at least " + schema.get("minProperties") + " properties");
        }
        if (schema.has("maxProperties") && inst.size() > schema.get("maxProperties").asInt()) {
            errors.add(path + ": must have at most " + schema.get("maxProperties") + " properties");
        }
        JsonNode props = schema.get("properties");
        JsonNode patterns = schema.get("patternProperties");
        Iterator<String> names = inst.fieldNames();
        while (names.hasNext()) {
            String name = names.next();
            boolean matched = false;
            if (props != null && props.has(name)) {
                matched = true;
                check(props.get(name), inst.get(name), path + "." + name, depth + 1);
            }
            if (patterns != null) {
                Iterator<String> pn = patterns.fieldNames();
                while (pn.hasNext()) {
                    String p = pn.next();
                    if (Pattern.compile(p).matcher(name).find()) {
                        matched = true;
                        check(patterns.get(p), inst.get(name), path + "." + name, depth + 1);
                    }
                }
            }
            if (!matched && schema.has("additionalProperties")) {
                JsonNode ap = schema.get("additionalProperties");
                if (ap.isBoolean() && !ap.booleanValue()) {
                    errors.add(path + ": additional property " + name + " is not allowed");
                } else if (ap.isObject()) {
                    check(ap, inst.get(name), path + "." + name, depth + 1);
                }
            }
        }
        if (schema.has("propertyNames")) {
            Iterator<String> all = inst.fieldNames();
            while (all.hasNext()) {
                check(schema.get("propertyNames"), MAPPER.getNodeFactory().textNode(all.next()), path, depth + 1);
            }
        }
        if (schema.has("dependencies")) {
            Iterator<String> dn = schema.get("dependencies").fieldNames();
            while (dn.hasNext()) {
                String k = dn.next();
                if (!inst.has(k)) {
                    continue;
                }
                JsonNode dep = schema.get("dependencies").get(k);
                if (dep.isArray()) {
                    for (JsonNode d : dep) {
                        if (!inst.has(d.asText())) {
                            errors.add(path + ": " + d.asText() + " is required when " + k + " is present");
                        }
                    }
                } else {
                    check(dep, inst, path, depth + 1);
                }
            }
        }
    }

    private void checkArray(JsonNode schema, JsonNode inst, String path, int depth) throws Exception {
        if (schema.has("minItems") && inst.size() < schema.get("minItems").asInt()) {
            errors.add(path + ": must have at least " + schema.get("minItems") + " items");
        }
        if (schema.has("maxItems") && inst.size() > schema.get("maxItems").asInt()) {
            errors.add(path + ": must have at most " + schema.get("maxItems") + " items");
        }
        if (schema.has("uniqueItems") && schema.get("uniqueItems").asBoolean()) {
            for (int i = 0; i < inst.size(); i++) {
                for (int j = i + 1; j < inst.size(); j++) {
                    if (inst.get(i).equals(inst.get(j))) {
                        errors.add(path + ": items " + i + " and " + j + " are equal");
                    }
                }
            }
        }
        JsonNode items = schema.get("items");
        for (int i = 0; i < inst.size(); i++) {
            JsonNode s = null;
            if (items != null && items.isArray()) {
                s = i < items.size() ? items.get(i) : schema.get("additionalItems");
            } else if (items != null) {
                s = items;
            }
            if (s != null) {
                check(s, inst.get(i), path + "." + i, depth + 1);
            }
        }
        if (schema.has("contains")) {
            boolean any = false;
            for (JsonNode e : inst) {
                any |= sub(schema.get("contains"), e, path, depth);
            }
            if (!any) {
                errors.add(path + ": must contain at least one item matching the schema");
            }
        }
    }

    private static boolean typeMatches(JsonNode type, JsonNode inst) {
        if (type.isArray()) {
            for (JsonNode t : type) {
                if (typeMatches(t, inst)) {
                    return true;
                }
            }
            return false;
        }
        return switch (type.asText()) {
            case "object" -> inst.isObject();
            case "array" -> inst.isArray();
            case "string" -> inst.isTextual();
            case "boolean" -> inst.isBoolean();
            case "null" -> inst.isNull();
            case "number" -> inst.isNumber();
            case "integer" -> inst.isIntegralNumber()
                    || (inst.isNumber() && inst.decimalValue().stripTrailingZeros().scale() <= 0);
            default -> false;
        };
    }
}
