use chrono::DateTime;
use regex::Regex;
use serde_json::Value;
use std::path::{Path, PathBuf};

#[allow(dead_code)]
pub fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/security_v2")
}

#[allow(dead_code)]
pub fn fixture(name: &str) -> Value {
    serde_json::from_slice(&std::fs::read(fixture_dir().join(name)).unwrap()).unwrap()
}

pub fn validates(schema: &Value, value: &Value) -> bool {
    validate_node(schema, schema, value)
}

fn validate_node(schema: &Value, root: &Value, value: &Value) -> bool {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        return local_ref(root, reference).is_some_and(|target| validate_node(target, root, value));
    }
    if schema
        .get("const")
        .is_some_and(|constant| value != constant)
        || schema
            .get("enum")
            .and_then(Value::as_array)
            .is_some_and(|values| !values.contains(value))
    {
        return false;
    }
    if schema
        .get("oneOf")
        .and_then(Value::as_array)
        .is_some_and(|branches| {
            branches
                .iter()
                .filter(|branch| validate_node(branch, root, value))
                .count()
                != 1
        })
        || schema
            .get("anyOf")
            .and_then(Value::as_array)
            .is_some_and(|branches| {
                !branches
                    .iter()
                    .any(|branch| validate_node(branch, root, value))
            })
        || schema
            .get("allOf")
            .and_then(Value::as_array)
            .is_some_and(|branches| {
                branches
                    .iter()
                    .any(|branch| !validate_node(branch, root, value))
            })
        || schema
            .get("not")
            .is_some_and(|negated| validate_node(negated, root, value))
    {
        return false;
    }
    if let Some(condition) = schema.get("if") {
        let branch = if validate_node(condition, root, value) {
            schema.get("then")
        } else {
            schema.get("else")
        };
        if branch.is_some_and(|branch| !validate_node(branch, root, value)) {
            return false;
        }
    }

    match schema.get("type").and_then(Value::as_str) {
        Some("object") if !value.is_object() => return false,
        Some("array") if !value.is_array() => return false,
        Some("string") if !value.is_string() => return false,
        Some("integer") if !value.is_i64() && !value.is_u64() => return false,
        Some("boolean") if !value.is_boolean() => return false,
        Some("null") if !value.is_null() => return false,
        _ => {}
    }

    if let Some(object) = value.as_object() {
        if schema
            .get("required")
            .and_then(Value::as_array)
            .is_some_and(|required| {
                required
                    .iter()
                    .any(|key| key.as_str().is_none_or(|key| !object.contains_key(key)))
            })
        {
            return false;
        }
        let properties = schema.get("properties").and_then(Value::as_object);
        if schema.get("additionalProperties") == Some(&Value::Bool(false))
            && object
                .keys()
                .any(|key| properties.is_none_or(|properties| !properties.contains_key(key)))
        {
            return false;
        }
        if let Some(properties) = properties
            && object.iter().any(|(key, value)| {
                properties
                    .get(key)
                    .is_some_and(|property| !validate_node(property, root, value))
            })
        {
            return false;
        }
        if outside_usize_bound(schema, "minProperties", object.len(), |actual, bound| {
            actual < bound
        }) || outside_usize_bound(schema, "maxProperties", object.len(), |actual, bound| {
            actual > bound
        }) {
            return false;
        }
    }

    if let Some(array) = value.as_array()
        && (schema
            .get("items")
            .is_some_and(|items| array.iter().any(|value| !validate_node(items, root, value)))
            || outside_usize_bound(schema, "minItems", array.len(), |actual, bound| {
                actual < bound
            })
            || outside_usize_bound(schema, "maxItems", array.len(), |actual, bound| {
                actual > bound
            })
            || schema.get("uniqueItems") == Some(&Value::Bool(true))
                && array
                    .iter()
                    .enumerate()
                    .any(|(index, value)| array[..index].contains(value)))
    {
        return false;
    }

    if let Some(string) = value.as_str() {
        let length = string.chars().count();
        if outside_usize_bound(schema, "minLength", length, |actual, bound| actual < bound)
            || outside_usize_bound(schema, "maxLength", length, |actual, bound| actual > bound)
            || schema
                .get("pattern")
                .and_then(Value::as_str)
                .is_some_and(|pattern| !matches_pattern(pattern, string))
            || schema.get("format").and_then(Value::as_str) == Some("date-time")
                && DateTime::parse_from_rfc3339(string).is_err()
        {
            return false;
        }
    }

    if let Some(integer) = integer_value(value)
        && (schema
            .get("minimum")
            .and_then(integer_value)
            .is_some_and(|minimum| integer < minimum)
            || schema
                .get("maximum")
                .and_then(integer_value)
                .is_some_and(|maximum| integer > maximum))
    {
        return false;
    }
    true
}

fn local_ref<'a>(schema: &'a Value, reference: &str) -> Option<&'a Value> {
    reference
        .strip_prefix("#/")?
        .split('/')
        .try_fold(schema, |node, part| node.get(part))
}

fn outside_usize_bound(
    schema: &Value,
    keyword: &str,
    actual: usize,
    outside: impl FnOnce(usize, usize) -> bool,
) -> bool {
    schema
        .get(keyword)
        .and_then(Value::as_u64)
        .and_then(|bound| usize::try_from(bound).ok())
        .is_some_and(|bound| outside(actual, bound))
}

fn integer_value(value: &Value) -> Option<i128> {
    value
        .as_i64()
        .map(i128::from)
        .or_else(|| value.as_u64().map(i128::from))
}

fn matches_pattern(pattern: &str, value: &str) -> bool {
    let Ok(regex) = Regex::new(pattern) else {
        return false;
    };
    regex.is_match(value)
}
