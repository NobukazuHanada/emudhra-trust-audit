use crate::{safe, versions};
use regex::Regex;
use serde_json::Value;
#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    pub pinned: bool,
}
fn dep(name: &str, v: &str, eco: &str, pinned: bool) -> Dependency {
    Dependency {
        name: if name == "nodejs" {
            "node".into()
        } else {
            name.to_lowercase()
        },
        version: v.trim().trim_start_matches('v').into(),
        ecosystem: eco.into(),
        pinned,
    }
}
fn rx(pattern: &str) -> Regex {
    Regex::new(pattern).expect("static parser regex")
}
fn json(text: &str) -> Result<Value, String> {
    let v: Value = serde_json::from_str(text).map_err(|_| "invalid JSON manifest/lockfile")?;
    if !v.is_object() {
        return Err("manifest/lockfile must be an object".into());
    }
    Ok(v)
}
pub fn parse(kind: &str, text: &str) -> Result<Vec<Dependency>, String> {
    let mut out = vec![];
    match kind {
        "npm-lock" => {
            let v = json(text)?;
            if let Some(pkgs) = v["packages"].as_object() {
                for (path, p) in pkgs {
                    let name = p["name"]
                        .as_str()
                        .unwrap_or_else(|| path.rsplit("node_modules/").next().unwrap_or(""));
                    if let Some(ver) = p["version"].as_str()
                        && !name.is_empty()
                    {
                        out.push(dep(name, ver, "npm", true));
                    }
                }
            } else {
                let mut stack = vec![&v["dependencies"]];
                while let Some(v) = stack.pop() {
                    if let Some(o) = v.as_object() {
                        for (n, p) in o {
                            if let Some(ver) = p["version"].as_str() {
                                out.push(dep(n, ver, "npm", true));
                            }
                            if p["dependencies"].is_object() {
                                stack.push(&p["dependencies"]);
                            }
                        }
                    }
                    if out.len() > 20000 {
                        return Err("dependency limit".into());
                    }
                }
            }
        }
        "package.json" => {
            let v = json(text)?;
            for section in ["dependencies", "devDependencies", "optionalDependencies"] {
                if let Some(o) = v[section].as_object() {
                    for (n, p) in o {
                        if let Some(s) = p.as_str() {
                            out.push(dep(n, s, "npm", versions::numeric(s).is_some()));
                        }
                    }
                }
            }
            if let Some(v) = v["engines"]["node"].as_str() {
                out.push(dep("node", v, "npm", false));
            }
        }
        "pipfile-lock" => {
            let v = json(text)?;
            for section in ["default", "develop"] {
                if let Some(o) = v[section].as_object() {
                    for (n, p) in o {
                        if let Some(s) = p["version"].as_str() {
                            out.push(dep(
                                n,
                                s.trim_start_matches('='),
                                "pypi",
                                s.starts_with("=="),
                            ));
                        }
                    }
                }
            }
        }
        "composer-lock" => {
            let v = json(text)?;
            for section in ["packages", "packages-dev"] {
                for p in safe::array(&v, section) {
                    if let (Some(n), Some(v)) = (p["name"].as_str(), p["version"].as_str()) {
                        out.push(dep(n, v, "packagist", true));
                    }
                }
            }
        }
        "cargo-lock" | "toml-lock" => {
            let v: toml::Value = text.parse().map_err(|_| "invalid TOML lockfile")?;
            if let Some(a) = v.get("package").and_then(toml::Value::as_array) {
                for p in a {
                    if let (Some(n), Some(v)) = (
                        p.get("name").and_then(toml::Value::as_str),
                        p.get("version").and_then(toml::Value::as_str),
                    ) {
                        out.push(dep(
                            n,
                            v,
                            if kind == "cargo-lock" {
                                "crates"
                            } else {
                                "pypi"
                            },
                            true,
                        ));
                    }
                }
            }
        }
        "requirements" => for c in rx(
            r"(?m)^\s*([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*(===|==|~=|>=|<=|>|<|!=)\s*([^\s;#\\]+)",
        )
        .captures_iter(text)
        {
            out.push(dep(&c[1], &c[3], "pypi", &c[2] == "==" || &c[2] == "==="));
        },
        "yarn-lock" => {
            let mut name = String::new();
            let yarn_version = rx(r#"^\s+version:?\s+"?([^"\s]+)"#);
            for line in text.lines() {
                if !line.starts_with(char::is_whitespace) && line.ends_with(':') {
                    let h = line
                        .trim_end_matches(':')
                        .split(',')
                        .next()
                        .unwrap_or("")
                        .trim_matches('"');
                    name = h.rsplit_once('@').map(|x| x.0).unwrap_or("").into();
                }
                if let Some(c) = yarn_version.captures(line)
                    && !name.is_empty()
                {
                    out.push(dep(&name, &c[1], "npm", true));
                }
            }
        }
        "pnpm-lock" => {
            for c in rx(r#"(?m)^\s{2,}['"]?/?((?:@[^/'"@\s]+/)?[^/'"@\s]+)[/@](\d[^('\":\s]*)"#)
                .captures_iter(text)
            {
                out.push(dep(&c[1], &c[2], "npm", true));
            }
        }
        "gemfile-lock" => {
            for c in rx(r"(?m)^\s{4}([A-Za-z0-9._-]+) \(([^)]+)\)$").captures_iter(text) {
                out.push(dep(&c[1], &c[2], "rubygems", true));
            }
        }
        "mix-lock" => {
            for c in rx(r#""([A-Za-z0-9_]+)":\s*\{:hex,\s*:[A-Za-z0-9_]+,\s*"([^"]+)""#)
                .captures_iter(text)
            {
                out.push(dep(&c[1], &c[2], "hex", true));
            }
        }
        "gosum" => {
            for c in rx(r"(?m)^(\S+)\s+v([^\s/]+)(?:/go\.mod)?\s+h1:").captures_iter(text) {
                out.push(dep(&c[1], &c[2], "golang", true));
            }
        }
        "go.mod" => {
            for c in rx(r"(?m)^(go\s+|toolchain\s+go)([0-9.]+)").captures_iter(text) {
                out.push(dep("go", &c[2], "golang", c[1].starts_with("toolchain")));
            }
        }
        ".nvmrc" | ".node-version" | ".go-version" => {
            let n = if kind == ".go-version" { "go" } else { "node" };
            let v = text
                .lines()
                .find(|s| !s.trim().is_empty() && !s.starts_with('#'))
                .unwrap_or("")
                .trim();
            out.push(dep(
                n,
                v,
                if n == "go" { "golang" } else { "npm" },
                versions::numeric(v).is_some_and(|v| v.len() >= 3),
            ));
        }
        ".tool-versions" => {
            for c in rx(r"(?m)^([a-zA-Z0-9_-]+)\s+([^\s#]+)").captures_iter(text) {
                let n = &c[1];
                out.push(dep(
                    n,
                    &c[2],
                    if n == "go" {
                        "golang"
                    } else if n == "node" || n == "nodejs" {
                        "npm"
                    } else {
                        "generic"
                    },
                    versions::numeric(&c[2]).is_some_and(|v| v.len() >= 3),
                ));
            }
        }
        "mise.toml" | ".mise.toml" => {
            let v: toml::Value = text.parse().map_err(|_| "invalid tool TOML")?;
            if let Some(o) = v.get("tools").and_then(toml::Value::as_table) {
                for (n, v) in o {
                    let ver = v.as_str().unwrap_or("");
                    out.push(dep(
                        n,
                        ver,
                        if n == "go" {
                            "golang"
                        } else if n == "node" || n == "nodejs" {
                            "npm"
                        } else {
                            "generic"
                        },
                        versions::numeric(ver).is_some_and(|v| v.len() >= 3),
                    ));
                }
            }
        }
        _ => return Err("unsupported dependency format".into()),
    }
    Ok(out)
}
