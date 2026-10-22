use crate::safe;
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};
const FILES: &[(&str, &[u8])] = &[
    (
        "incidents/emudhra-2026.json",
        include_bytes!("../data/incidents/emudhra-2026.json"),
    ),
    (
        "policies/fixed-versions.json",
        include_bytes!("../data/policies/fixed-versions.json"),
    ),
    (
        "rules/insecure-tls.json",
        include_bytes!("../data/rules/insecure-tls.json"),
    ),
    (
        "rules/project-inventory.json",
        include_bytes!("../data/rules/project-inventory.json"),
    ),
    (
        "schema/incident-v1.json",
        include_bytes!("../data/schema/incident-v1.json"),
    ),
    (
        "schema/policy-v1.json",
        include_bytes!("../data/schema/policy-v1.json"),
    ),
    (
        "schema/ruleset-v1.json",
        include_bytes!("../data/schema/ruleset-v1.json"),
    ),
];
pub struct Data {
    pub incident: Value,
    pub policy: Value,
    pub rules: Value,
    pub inventory: Value,
    pub payloads: Vec<Value>,
}
impl Data {
    pub fn load(dir: Option<&Path>) -> Result<Self, String> {
        let checksum = if let Some(d) = dir {
            safe::read(&d.join("checksums.json"), 1_048_576, false)?
        } else {
            include_bytes!("../data/checksums.json").to_vec()
        };
        let check: Value =
            serde_json::from_slice(&checksum).map_err(|_| "invalid checksum manifest")?;
        if safe::string(&check, "algorithm") != "sha256" {
            return Err("unsupported checksum algorithm".into());
        }
        let mut values = BTreeMap::new();
        for (name, embedded) in FILES {
            let b = if let Some(d) = dir {
                safe::read(&d.join(name), 1_048_576, false)?
            } else {
                embedded.to_vec()
            };
            if check["files"][name].as_str() != Some(&safe::digest(&safe::normalize(&b))) {
                return Err(format!("indicator integrity mismatch: {name}"));
            }
            let v: Value = serde_json::from_slice(&b).map_err(|_| "invalid indicator JSON")?;
            values.insert(*name, v);
        }
        if check["files"].as_object().map(|o| o.len()) != Some(FILES.len()) {
            return Err("unexpected checksum entries".into());
        }
        for (file, schema) in [
            ("incidents/emudhra-2026.json", "schema/incident-v1.json"),
            ("policies/fixed-versions.json", "schema/policy-v1.json"),
            ("rules/insecure-tls.json", "schema/ruleset-v1.json"),
            ("rules/project-inventory.json", "schema/ruleset-v1.json"),
        ] {
            validate(&values[file], &values[schema])?;
            if safe::string(&values[file], "data_version").is_empty()
                || safe::array(&values[file], "sources").is_empty()
            {
                return Err("indicator provenance missing".into());
            }
        }
        Ok(Self {
            incident: values["incidents/emudhra-2026.json"].clone(),
            policy: values["policies/fixed-versions.json"].clone(),
            rules: values["rules/insecure-tls.json"].clone(),
            inventory: values["rules/project-inventory.json"].clone(),
            payloads: values.into_values().collect(),
        })
    }
    pub fn sources(&self) -> Vec<Value> {
        [&self.incident,&self.policy,&self.rules,&self.inventory].iter().map(|v|json!({"data_version":v["data_version"],"as_of":v["as_of"],"sources":v["sources"]})).collect()
    }
    pub fn checksums(dir: &Path) -> Result<Value, String> {
        let mut hashes = BTreeMap::new();
        for (name, _) in FILES {
            hashes.insert(
                *name,
                safe::digest(&safe::normalize(&safe::read(
                    &dir.join(name),
                    1_048_576,
                    false,
                )?)),
            );
        }
        Ok(
            json!({"schema_version":1,"algorithm":"sha256","normalization":"CRLF and CR to LF; all other bytes unchanged","files":hashes}),
        )
    }
}
fn validate(v: &Value, s: &Value) -> Result<(), String> {
    let valid = match safe::string(s, "type") {
        "object" => v.is_object(),
        "array" => v.is_array(),
        "string" => v.is_string(),
        "integer" => v.is_i64() || v.is_u64(),
        "boolean" => v.is_boolean(),
        _ => true,
    };
    if !valid {
        return Err("indicator schema type mismatch".into());
    }
    if let Some(c) = s.get("const")
        && v != c
    {
        return Err("indicator schema constant mismatch".into());
    }
    if let Some(e) = s.get("enum").and_then(Value::as_array)
        && !e.contains(v)
    {
        return Err("indicator schema enum mismatch".into());
    }
    if let Some(o) = v.as_object() {
        for k in safe::list(s, "required") {
            if !o.contains_key(&k) {
                return Err("indicator required field missing".into());
            }
        }
        if let Some(props) = s["properties"].as_object() {
            for (k, sub) in props {
                if let Some(value) = o.get(k) {
                    validate(value, sub)?;
                }
            }
        }
    }
    if let Some(a) = v.as_array() {
        if s["minItems"]
            .as_u64()
            .is_some_and(|n| a.len() < (n as usize))
        {
            return Err("indicator array too short".into());
        }
        if let Some(sub) = s.get("items") {
            for value in a {
                validate(value, sub)?;
            }
        }
    }
    if let Some(t) = v.as_str() {
        if s["minLength"]
            .as_u64()
            .is_some_and(|n| t.len() < (n as usize))
        {
            return Err("indicator string too short".into());
        }
        if let Some(p) = s["pattern"].as_str()
            && !regex::Regex::new(p)
                .map_err(|_| "invalid schema pattern")?
                .is_match(t)
        {
            return Err("indicator string schema mismatch".into());
        }
    }
    Ok(())
}
