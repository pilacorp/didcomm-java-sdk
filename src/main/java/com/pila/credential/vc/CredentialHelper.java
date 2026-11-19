package com.pila.credential.vc;

import com.pila.credential.common.util.Rfc3339;
import com.pila.credential.common.util.VCUtil;

import java.time.Instant;
import java.util.*;

/**
 * Helper functions for credential serialization and parsing.
 */
public class CredentialHelper {

    /**
     * Serializes CredentialContents into a CredentialData.
     */
    public static CredentialData serializeCredentialContents(CredentialContents vcc) throws Exception {
        if (vcc == null) {
            throw new IllegalArgumentException("credential contents is nil");
        }

        // Validate that at least one essential field is present
        if ((vcc.getContext() == null || vcc.getContext().isEmpty())
                && (vcc.getId() == null || vcc.getId().isEmpty())
                && (vcc.getIssuer() == null || vcc.getIssuer().isEmpty())) {
            throw new IllegalArgumentException("credential contents must have at least one of: context, ID, or issuer");
        }

        CredentialData vcJSON = new CredentialData();

        if (vcc.getContext() != null && !vcc.getContext().isEmpty()) {
            List<Object> validatedContext = VCUtil.serializeContexts(vcc.getContext());
            vcJSON.put("@context", validatedContext);
        }

        if (vcc.getId() != null && !vcc.getId().isEmpty()) {
            vcJSON.put("id", vcc.getId());
        }

        if (vcc.getTypes() != null && !vcc.getTypes().isEmpty()) {
            vcJSON.put("type", VCUtil.serializeTypes(vcc.getTypes()));
        }

        if (vcc.getSubject() != null && !vcc.getSubject().isEmpty()) {
            vcJSON.put("credentialSubject", serializeSubjects(vcc.getSubject()));
        }

        if (vcc.getIssuer() != null && !vcc.getIssuer().isEmpty()) {
            vcJSON.put("issuer", vcc.getIssuer());
        }

        if (vcc.getSchemas() != null && !vcc.getSchemas().isEmpty()) {
            vcJSON.put("credentialSchema", serializeSchemas(vcc.getSchemas()));
        }

        if (vcc.getCredentialStatus() != null && !vcc.getCredentialStatus().isEmpty()) {
            for (int i = 0; i < vcc.getCredentialStatus().size(); i++) {
                String type = vcc.getCredentialStatus().get(i).getType();
                if (type == null || type.isEmpty()) {
                    throw new IllegalArgumentException("credentialStatus[" + i + "].type is required");
                }
            }
            vcJSON.put("credentialStatus", serializeStatuses(vcc.getCredentialStatus()));
        }

        if (vcc.getTermsOfUse() != null && !vcc.getTermsOfUse().isEmpty()) {
            List<Object> terms = new ArrayList<>();
            for (int i = 0; i < vcc.getTermsOfUse().size(); i++) {
                TermsOfUse t = vcc.getTermsOfUse().get(i);
                if (t.getType() == null || t.getType().isEmpty()) {
                    throw new IllegalArgumentException("termsOfUse[" + i + "].type is required");
                }
                terms.add(serializeTermsOfUse(t));
            }
            vcJSON.put("termsOfUse", terms);
        }

        if (vcc.getValidFrom() != null) {
            vcJSON.put("validFrom", Rfc3339.format(vcc.getValidFrom()));
        }

        if (vcc.getValidUntil() != null) {
            vcJSON.put("validUntil", Rfc3339.format(vcc.getValidUntil()));
        }

        // Shared by every credential type, so all of them reject a credential missing a required property.
        CredentialSupport.requireCredentialProperties(vcJSON);

        return vcJSON;
    }

    /** Type is required by the W3C data model, so it is always written. */
    public static CredentialData serializeTermsOfUse(TermsOfUse term) {
        CredentialData result = new CredentialData();
        result.put("type", term.getType());
        if (term.getId() != null && !term.getId().isEmpty()) {
            result.put("id", term.getId());
        }
        return result;
    }

    /** Parses termsOfUse (single object or array). */
    public static void parseTermsOfUse(CredentialData c, CredentialContents contents) throws Exception {
        Object raw = c.get("termsOfUse");
        if (raw == null) {
            return;
        }
        List<Object> items = raw instanceof List<?> l ? new ArrayList<>(l) : List.of(raw);
        for (Object item : items) {
            if (!(item instanceof Map<?, ?> m)) {
                throw new Exception("unsupported termsOfUse format: "
                        + (item != null ? item.getClass().getName() : "null"));
            }
            TermsOfUse t = new TermsOfUse();
            if (m.get("id") instanceof String id) {
                t.setId(id);
            }
            if (m.get("type") instanceof String type) {
                t.setType(type);
            }
            contents.getTermsOfUse().add(t);
        }
    }

    /**
     * Serializes subjects to JSON.
     */
    public static Object serializeSubjects(List<Subject> subjects) {
        if (subjects == null || subjects.isEmpty()) {
            return null;
        }
        if (subjects.size() == 1) {
            return serializeSubject(subjects.get(0));
        }
        return VCUtil.mapSlice(subjects, CredentialHelper::serializeSubject);
    }

    /**
     * Serializes a single subject to JSON.
     */
    public static CredentialData serializeSubject(Subject subject) {
        CredentialData jsonObj = new CredentialData(VCUtil.shallowCopyObj(subject.getCustomFields()));
        if (subject.getId() != null && !subject.getId().isEmpty()) {
            jsonObj.put("id", subject.getId());
        }
        return jsonObj;
    }

    /**
     * Serializes schemas to JSON.
     */
    public static Object serializeSchemas(List<Schema> schemas) {
        if (schemas == null || schemas.isEmpty()) {
            return null;
        }
        if (schemas.size() == 1) {
            return serializeSchema(schemas.get(0));
        }
        return VCUtil.mapSlice(schemas, CredentialHelper::serializeSchema);
    }

    /**
     * Serializes a single schema to JSON.
     */
    public static CredentialData serializeSchema(Schema schema) {
        CredentialData result = new CredentialData();
        result.put("id", schema.getId());
        result.put("type", schema.getType());
        return result;
    }

    /**
     * Serializes statuses to JSON.
     */
    public static Object serializeStatuses(List<Status> statuses) {
        if (statuses == null || statuses.isEmpty()) {
            return null;
        }
        if (statuses.size() == 1) {
            return serializeStatus(statuses.get(0));
        }
        return VCUtil.mapSlice(statuses, CredentialHelper::serializeStatus);
    }

    /**
     * Serializes a single status to JSON.
     */
    public static CredentialData serializeStatus(Status status) {
        CredentialData result = new CredentialData();
        if (status.getId() != null && !status.getId().isEmpty()) {
            result.put("id", status.getId());
        }
        if (status.getType() != null && !status.getType().isEmpty()) {
            result.put("type", status.getType());
        }
        if (status.getStatusPurpose() != null && !status.getStatusPurpose().isEmpty()) {
            result.put("statusPurpose", status.getStatusPurpose());
        }
        if (status.getStatusListIndex() != null && !status.getStatusListIndex().isEmpty()) {
            result.put("statusListIndex", status.getStatusListIndex());
        }
        if (status.getStatusListCredential() != null && !status.getStatusListCredential().isEmpty()) {
            result.put("statusListCredential", status.getStatusListCredential());
        }
        return result;
    }

    /**
     * Parses context from CredentialData.
     */
    public static void parseContext(CredentialData c, CredentialContents contents) throws Exception {
        Object contextObj = c.get("@context");
        if (contextObj instanceof List) {
            @SuppressWarnings("unchecked")
            List<Object> context = (List<Object>) contextObj;
            for (Object ctx : context) {
                if (ctx instanceof String || ctx instanceof Map) {
                    contents.getContext().add(ctx);
                } else {
                    throw new Exception(
                            "unsupported context type: " + (ctx != null ? ctx.getClass().getName() : "null"));
                }
            }
        }
    }

    /**
     * Parses ID from CredentialData.
     */
    public static void parseID(CredentialData c, CredentialContents contents) {
        Object idObj = c.get("id");
        if (idObj instanceof String) {
            contents.setId((String) idObj);
        }
    }

    /**
     * Parses types from CredentialData.
     */
    public static void parseTypes(CredentialData c, CredentialContents contents) throws Exception {
        Object typeObj = c.get("type");
        if (typeObj instanceof String) {
            contents.getTypes().add((String) typeObj);
        } else if (typeObj instanceof List) {
            @SuppressWarnings("unchecked")
            List<Object> types = (List<Object>) typeObj;
            for (Object t : types) {
                if (t instanceof String) {
                    contents.getTypes().add((String) t);
                }
            }
        } else if (typeObj != null) {
            throw new Exception("unsupported type field: " + typeObj.getClass().getName());
        }
    }

    /**
     * Parses issuer from CredentialData.
     */
    public static void parseIssuer(CredentialData c, CredentialContents contents) {
        Object issuerObj = c.get("issuer");
        if (issuerObj instanceof String) {
            contents.setIssuer((String) issuerObj);
        }
    }

    /**
     * Parses dates from CredentialData.
     */
    public static void parseDates(CredentialData c, CredentialContents contents) throws Exception {
        Object validFromObj = c.get("validFrom");
        if (validFromObj instanceof String) {
            try {
                contents.setValidFrom(Rfc3339.parse((String) validFromObj));
            } catch (Exception e) {
                throw new Exception("failed to parse validFrom: " + e.getMessage(), e);
            }
        }

        Object validUntilObj = c.get("validUntil");
        if (validUntilObj instanceof String) {
            try {
                contents.setValidUntil(Rfc3339.parse((String) validUntilObj));
            } catch (Exception e) {
                throw new Exception("failed to parse validUntil: " + e.getMessage(), e);
            }
        }
    }

    /**
     * Parses subject from CredentialData.
     */
    public static void parseSubject(CredentialData c, CredentialContents contents) throws Exception {
        Object subjectRaw = c.get("credentialSubject");
        if (subjectRaw == null) {
            return;
        }

        if (subjectRaw instanceof String) {
            contents.getSubject().add(new Subject((String) subjectRaw, new HashMap<>()));
        } else if (subjectRaw instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> subjectMap = (Map<String, Object>) subjectRaw;
            Subject parsed = subjectFromJSON(new CredentialData(subjectMap));
            contents.getSubject().add(parsed);
        } else if (subjectRaw instanceof List) {
            @SuppressWarnings("unchecked")
            List<Object> subjects = (List<Object>) subjectRaw;
            for (Object raw : subjects) {
                if (raw instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> subjectMap = (Map<String, Object>) raw;
                    Subject parsed = subjectFromJSON(new CredentialData(subjectMap));
                    contents.getSubject().add(parsed);
                } else {
                    throw new Exception(
                            "unsupported subject format: " + (raw != null ? raw.getClass().getName() : "null"));
                }
            }
        } else {
            throw new Exception(
                    "unsupported subject format: " + (subjectRaw != null ? subjectRaw.getClass().getName() : "null"));
        }
    }

    /**
     * Creates a Subject from JSON.
     */
    public static Subject subjectFromJSON(CredentialData subjectObj) throws Exception {
        Map<String, Object>[] split = VCUtil.splitJSONObj(subjectObj, "id");
        Map<String, Object> fieldsMap = split[0];
        Map<String, Object> rest = split[1];

        String id = parseStringField(new CredentialData(fieldsMap), "id");
        return new Subject(id, rest);
    }

    /**
     * Parses schema from CredentialData.
     */
    public static void parseSchema(CredentialData c, CredentialContents contents) throws Exception {
        Object schemaRaw = c.get("credentialSchema");
        if (schemaRaw == null) {
            return;
        }

        if (schemaRaw instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> schemaMap = (Map<String, Object>) schemaRaw;
            Schema parsed = parseSchemaID(schemaMap);
            contents.getSchemas().add(parsed);
        } else if (schemaRaw instanceof List) {
            @SuppressWarnings("unchecked")
            List<Object> schemas = (List<Object>) schemaRaw;
            for (Object raw : schemas) {
                Schema parsed = parseSchemaID(raw);
                contents.getSchemas().add(parsed);
            }
        } else {
            throw new Exception(
                    "unsupported schema format: " + (schemaRaw != null ? schemaRaw.getClass().getName() : "null"));
        }
    }

    /**
     * Parses status from CredentialData.
     */
    public static void parseStatus(CredentialData c, CredentialContents contents) throws Exception {
        Object statusRaw = c.get("credentialStatus");
        if (statusRaw == null) {
            return;
        }

        if (statusRaw instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> statusMap = (Map<String, Object>) statusRaw;
            Status parsed = parseStatusEntry(statusMap);
            contents.getCredentialStatus().add(parsed);
        } else if (statusRaw instanceof List) {
            @SuppressWarnings("unchecked")
            List<Object> statuses = (List<Object>) statusRaw;
            for (Object raw : statuses) {
                if (raw instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> statusMap = (Map<String, Object>) raw;
                    Status parsed = parseStatusEntry(statusMap);
                    contents.getCredentialStatus().add(parsed);
                } else {
                    throw new Exception(
                            "unsupported status format: " + (raw != null ? raw.getClass().getName() : "null"));
                }
            }
        } else {
            throw new Exception(
                    "unsupported status format: " + (statusRaw != null ? statusRaw.getClass().getName() : "null"));
        }
    }

    /**
     * Parses a single status entry.
     */
    public static Status parseStatusEntry(Map<String, Object> status) {
        Status s = new Status();
        if (status.get("id") instanceof String) {
            s.setId((String) status.get("id"));
        }
        if (status.get("type") instanceof String) {
            s.setType((String) status.get("type"));
        }
        if (status.get("statusPurpose") instanceof String) {
            s.setStatusPurpose((String) status.get("statusPurpose"));
        }
        if (status.get("statusListIndex") instanceof String) {
            s.setStatusListIndex((String) status.get("statusListIndex"));
        }
        if (status.get("statusListCredential") instanceof String) {
            s.setStatusListCredential((String) status.get("statusListCredential"));
        }
        return s;
    }

    /**
     * Parses a Schema from a value.
     */
    public static Schema parseSchemaID(Object value) throws Exception {
        Schema schema = new Schema();
        if (value instanceof String) {
            schema.setId((String) value);
        } else if (value instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> schemaMap = (Map<String, Object>) value;
            if (schemaMap.get("id") instanceof String) {
                schema.setId((String) schemaMap.get("id"));
            }
            if (schemaMap.get("type") instanceof String) {
                schema.setType((String) schemaMap.get("type"));
            }
        } else {
            throw new Exception("invalid schema format: " + (value != null ? value.getClass().getName() : "null"));
        }
        return schema;
    }

    /**
     * Parses a string field from a JSON object.
     */
    public static String parseStringField(CredentialData obj, String fieldName) throws Exception {
        Object value = obj.get(fieldName);
        if (value != null) {
            if (value instanceof String) {
                return (String) value;
            }
            throw new Exception("field \"" + fieldName + "\" must be a string, got " + value.getClass().getName());
        }
        return null;
    }

    /**
     * Validates a credential against every credentialSchema it names (JSON Schema draft-07 core; see
     * {@link com.pila.credential.common.schema.JsonSchemaValidator}).
     */
    public static void validateCredential(CredentialData m, CredentialOptions opts) throws Exception {
        CredentialSupport.validateSchema(m, opts);
    }

    /**
     * Converts a value to an array.
     */
    public static List<Object> convertToArray(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof List) {
            @SuppressWarnings("unchecked")
            List<Object> list = (List<Object>) value;
            return list;
        }
        List<Object> result = new ArrayList<>();
        result.add(value);
        return result;
    }
}
