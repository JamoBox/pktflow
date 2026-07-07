//! A small, purpose-built JSON Schema checker (08.5): supports exactly
//! the constructs `schema/streams-v1.json` uses (type, const, enum,
//! required, properties, propertyNames, additionalProperties, items,
//! minimum, allOf/if/then, local `#/$defs/...` refs) — not a general
//! validator. Reusing a full JSON-Schema crate for one hand-authored,
//! non-recursive schema would pull in far more than this needs; see
//! the 08.5 commit for why `jsonschema` (105 transitive deps, mostly
//! ICU/wasm-bindgen for format/regex support this schema never uses)
//! was rejected in favor of this.

use std::path::Path;

use serde_json::Value as Json;

pub fn load_schema() -> Json {
    load_schema_file("streams-v1.json")
}

/// 10.3's table/drill-down/manifest schema.
pub fn load_unknown_schema() -> Json {
    load_schema_file("unknown-v1.json")
}

fn load_schema_file(name: &str) -> Json {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schema")
        .join(name);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&text).expect("schema file is valid JSON")
}

/// Validates `instance` against `schema_root/$defs/<def_name_or_root>`.
/// `def_name` of `""` validates against the schema's own top level.
pub fn validate(schema_root: &Json, def_name: &str, instance: &Json) -> Result<(), String> {
    let defs = schema_root.get("$defs").cloned().unwrap_or(Json::Null);
    let schema = if def_name.is_empty() {
        schema_root.clone()
    } else {
        defs.get(def_name)
            .unwrap_or_else(|| panic!("no $defs/{def_name} in schema"))
            .clone()
    };
    check(&schema, instance, &defs, "$")
}

fn json_type_name(v: &Json) -> &'static str {
    match v {
        Json::Null => "null",
        Json::Bool(_) => "boolean",
        Json::Number(n) if n.is_i64() || n.is_u64() => "integer",
        Json::Number(_) => "number",
        Json::String(_) => "string",
        Json::Array(_) => "array",
        Json::Object(_) => "object",
    }
}

fn check(schema: &Json, instance: &Json, defs: &Json, path: &str) -> Result<(), String> {
    if let Some(r) = schema.get("$ref").and_then(Json::as_str) {
        let name = r
            .strip_prefix("#/$defs/")
            .unwrap_or_else(|| panic!("only local #/$defs refs supported, got {r}"));
        let target = defs
            .get(name)
            .unwrap_or_else(|| panic!("$ref target $defs/{name} missing"));
        return check(target, instance, defs, path);
    }

    if let Some(constv) = schema.get("const") {
        if instance != constv {
            return Err(format!("{path}: expected const {constv}, got {instance}"));
        }
    }
    if let Some(enumv) = schema.get("enum").and_then(Json::as_array) {
        if !enumv.contains(instance) {
            return Err(format!("{path}: {instance} not in enum {enumv:?}"));
        }
    }
    if let Some(t) = schema.get("type") {
        let types: Vec<&str> = match t {
            Json::String(s) => vec![s.as_str()],
            Json::Array(a) => a.iter().filter_map(Json::as_str).collect(),
            _ => vec![],
        };
        let actual = json_type_name(instance);
        if !types.is_empty() && !types.contains(&actual) {
            return Err(format!(
                "{path}: expected type {types:?}, got {actual} ({instance})"
            ));
        }
    }
    if let Some(min) = schema.get("minimum").and_then(Json::as_f64) {
        if let Some(n) = instance.as_f64() {
            if n < min {
                return Err(format!("{path}: {n} < minimum {min}"));
            }
        }
    }

    if let Some(obj) = instance.as_object() {
        if let Some(required) = schema.get("required").and_then(Json::as_array) {
            for req in required {
                let key = req.as_str().expect("required entries are strings");
                if !obj.contains_key(key) {
                    return Err(format!("{path}: missing required property {key:?}"));
                }
            }
        }
        let declared_props = schema.get("properties").and_then(Json::as_object);
        if let Some(props) = declared_props {
            for (k, v) in obj {
                if let Some(prop_schema) = props.get(k) {
                    check(prop_schema, v, defs, &format!("{path}.{k}"))?;
                }
            }
        }
        if let Some(prop_names) = schema.get("propertyNames") {
            for k in obj.keys() {
                check(
                    prop_names,
                    &Json::String(k.clone()),
                    defs,
                    &format!("{path}.<key {k:?}>"),
                )?;
            }
        }
        if let Some(additional) = schema.get("additionalProperties") {
            if additional.is_object() {
                let declared: std::collections::HashSet<&str> = declared_props
                    .map(|m| m.keys().map(String::as_str).collect())
                    .unwrap_or_default();
                for (k, v) in obj {
                    if !declared.contains(k.as_str()) {
                        check(additional, v, defs, &format!("{path}.{k}"))?;
                    }
                }
            }
        }
    }

    if let Some(arr) = instance.as_array() {
        if let Some(items_schema) = schema.get("items") {
            for (i, item) in arr.iter().enumerate() {
                check(items_schema, item, defs, &format!("{path}[{i}]"))?;
            }
        }
    }

    if let Some(all_of) = schema.get("allOf").and_then(Json::as_array) {
        for sub in all_of {
            check_conditional(sub, instance, defs, path)?;
        }
    }
    Ok(())
}

fn check_conditional(
    schema: &Json,
    instance: &Json,
    defs: &Json,
    path: &str,
) -> Result<(), String> {
    if let (Some(if_schema), Some(then_schema)) = (schema.get("if"), schema.get("then")) {
        if if_matches(if_schema, instance) {
            return check(then_schema, instance, defs, path);
        }
        return Ok(());
    }
    check(schema, instance, defs, path)
}

/// Only supports `{"properties": {"key": {"const": v}}}` conditions —
/// the only `if` shape this schema uses (rollup `kind` discrimination).
fn if_matches(schema: &Json, instance: &Json) -> bool {
    let Some(props) = schema.get("properties").and_then(Json::as_object) else {
        return false;
    };
    props.iter().all(|(k, sub)| {
        sub.get("const")
            .is_none_or(|constv| instance.get(k) == Some(constv))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn schema_loads_and_accepts_a_minimal_valid_document() {
        let schema = load_schema();
        let doc = json!({"pktflow": 1, "mode": "offline", "source": "f.pcap"});
        validate(&schema, "", &doc).expect("minimal document is valid");
    }

    #[test]
    fn unknown_schema_loads_and_accepts_a_minimal_valid_document() {
        let schema = load_unknown_schema();
        let doc = json!({"pktflow": 1, "groups": []});
        validate(&schema, "", &doc).expect("minimal document is valid");
    }

    #[test]
    fn schema_rejects_a_wrong_pktflow_version() {
        let schema = load_schema();
        let doc = json!({"pktflow": 2, "mode": "offline", "source": "f.pcap"});
        assert!(validate(&schema, "", &doc).is_err(), "version 2 must fail");
    }

    #[test]
    fn schema_rejects_a_stream_missing_a_required_field() {
        let schema = load_schema();
        let doc = json!({"id": 1, "protocol": "tcp"});
        assert!(
            validate(&schema, "stream", &doc).is_err(),
            "missing endpoint_a/etc. must fail"
        );
    }

    #[test]
    fn schema_rejects_an_unknown_stop_class_key() {
        let schema = load_schema();
        let doc = json!({
            "packets": 1, "bytes": 1,
            "stop_classes": {"not_a_real_class": 1},
            "streams": {}, "capture_drops": 0,
        });
        assert!(validate(&schema, "summary", &doc).is_err());
    }
}
