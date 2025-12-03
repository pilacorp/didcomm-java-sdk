package com.pila.credential.vc;

import lombok.Data;

/**
 * Schema represents a credential schema with an ID and type.
 * 
 * TODO: Implement JSON schema validation support
 * - Load schema from URL or local file
 * - Parse JSON schema structure
 * - Validate credential against schema
 * - Support schema versioning
 * - Cache schemas for performance
 */
@Data
public class Schema {
    private String id;
    private String type;

    // TODO: Add schema validation methods:
    // - validateCredential(Credential credential): boolean
    // - loadSchema(String schemaUrl): Schema
    // - getSchemaDefinition(): JsonNode (full schema definition)
}
