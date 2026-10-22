use crate::{
    certs,
    data::Data,
    model::{Finding, Report},
    parsers, safe, versions,
};
use regex::{Regex, RegexBuilder};
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
};

pub fn matches(path: &str, pattern: &str) -> bool {
    glob::Pattern::new(pattern)
        .is_ok_and(|p| p.matches(path) || p.matches(path.rsplit('/').next().unwrap_or(path)))
}
pub struct Rule {
    value: Value,
    regex: Regex,
    exclude: Option<Regex>,
}
pub fn rules(data: &Data) -> Result<Vec<Rule>, String> {
    safe::array(&data.rules, "rules")
        .iter()
        .map(|v| {
            let flags = safe::list(v, "flags");
            let regex = RegexBuilder::new(safe::string(v, "pattern"))
                .case_insensitive(flags.iter().any(|s| s == "i"))
                .multi_line(flags.iter().any(|s| s == "m"))
                .dot_matches_new_line(flags.iter().any(|s| s == "s"))
                .size_limit(2_000_000)
                .build()
                .map_err(|_| "invalid rule regex")?;
            let exclude = v["exclude_match"]
                .as_str()
                .map(Regex::new)
                .transpose()
                .map_err(|_| "invalid exclusion regex")?;
            Ok(Rule {
                value: v.clone(),
                regex,
                exclude,
            })
        })
        .collect()
}
pub fn tls(
    text: &str,
    label: &str,
    documentation: bool,
    rules: &[Rule],
    scope: &str,
) -> Vec<Finding> {
    let mut out = vec![];
    for rule in rules {
        if let Some(m) = rule.regex.find_iter(text).find(|m| {
            !rule
                .exclude
                .as_ref()
                .is_some_and(|r| r.is_match(m.as_str()))
        }) {
            let v = &rule.value;
            let mut f = Finding::new(
                &format!("{scope}-{}", safe::string(v, "id")),
                safe::string(v, "title"),
                if documentation {
                    "suspicious"
                } else {
                    safe::string(v, "status")
                },
                if documentation || safe::string(v, "severity") == "medium" {
                    "review_required"
                } else {
                    "action_required"
                },
            )
            .at(label)
            .evidence(
                "line",
                &(text[..m.start()].bytes().filter(|b| *b == b'\n').count() + 1).to_string(),
            );
            f.confidence = if documentation {
                "low"
            } else {
                safe::string(v, "confidence")
            }
            .into();
            f.severity = if documentation {
                "info"
            } else {
                safe::string(v, "severity")
            }
            .into();
            f.references = safe::list(v, "references");
            f.remediation = safe::list(v, "remediation");
            if documentation {
                f.evidence.push(serde_json::json!({"what":"context","value":"documentation mention; confirm production use"}));
            } else {
                f.tags = safe::list(v, "tags");
            }
            out.push(f);
        }
    }
    out
}
fn dependencies(kind: &str, text: &str, label: &str, data: &Data, report: &mut Report) -> usize {
    match parsers::parse(kind, text) {
        Ok(deps) => {
            if deps.is_empty() && !text.trim().is_empty() {
                report.findings.push(
                    Finding::gap(
                        "PROJECT-DEPENDENCY-COVERAGE",
                        "Manifest or lockfile yielded no assessable dependencies",
                    )
                    .at(label),
                );
            }
            for dep in &deps {
                for entry in safe::array(&data.policy, "packages") {
                    if dep.name == safe::string(entry, "name").to_lowercase()
                        && dep.ecosystem == safe::string(entry, "ecosystem")
                    {
                        report.findings.push(versions::finding(
                            safe::string(entry, "name"),
                            &dep.version,
                            dep.pinned,
                            entry,
                            "PROJECT",
                            label,
                        ));
                    }
                }
                for entry in safe::array(&data.policy, "watchlist") {
                    if dep.name == safe::string(entry, "name").to_lowercase() {
                        report.findings.push(
                            Finding::gap(
                                "PROJECT-WATCHLIST-DEPENDENCY",
                                "Independent trust component has no recorded fixed version",
                            )
                            .evidence("component", safe::string(entry, "name"))
                            .at(label),
                        );
                    }
                }
            }
            deps.len()
        }
        Err(_) => {
            report.findings.push(
                Finding::gap(
                    "PROJECT-DEPENDENCY-COVERAGE",
                    "Dependency file is malformed or unsupported",
                )
                .at(label),
            );
            0
        }
    }
}
pub fn audit(path: &Path, data: &Data, containers: bool) -> Result<Report, String> {
    if safe::is_link(&fs::symlink_metadata(path).map_err(|_| "project unavailable")?) {
        return Err("project root is linked".into());
    }
    let root = path.canonicalize().map_err(|_| "project unavailable")?;
    if !root.is_dir() {
        return Err("project is not a directory".into());
    }
    let mut report = Report::new("project");
    report.data_sources = data.sources();
    let rules = rules(data)?;
    let scan = &data.rules["scan"];
    let max_files = scan["max_files"].as_u64().unwrap_or(20000).min(20000) as usize;
    let limit = scan["max_file_bytes"]
        .as_u64()
        .unwrap_or(1048576)
        .min(1048576) as usize;
    let excluded = safe::list(scan, "exclude_dirs");
    let mut ignores = vec![];
    let ignore = Path::new(".ca-trust-audit-ignore");
    if fs::symlink_metadata(root.join(ignore)).is_ok() {
        match safe::project_read(&root, ignore, 65536).and_then(|b| safe::text(&b)) {
            Ok(t) => {
                for line in t
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                {
                    if glob::Pattern::new(line).is_err() {
                        report.findings.push(Finding::gap(
                            "PROJECT-IGNORE-INVALID",
                            "Invalid exclusion pattern",
                        ));
                    } else {
                        ignores.push(line.to_owned());
                    }
                }
            }
            Err(_) => report.findings.push(Finding::gap(
                "PROJECT-IGNORE-UNREADABLE",
                "Exclusion file cannot be assessed",
            )),
        }
    }
    let ci_version = Regex::new(r#"(?m)(node|go)-version:\s*['"]?([0-9]+(?:\.[0-9]+)*)['"]?\s*$"#)
        .expect("static regex");
    let refresh_patterns: Vec<_> = safe::list(&data.inventory, "container_ca_update_patterns")
        .iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect();
    let mut stack = vec![PathBuf::new()];
    let (mut walked, mut skipped, mut deps, mut manifest_count, mut locks) = (0, 0, 0, 0, 0);
    while let Some(rel) = stack.pop() {
        if walked >= max_files {
            report.findings.push(Finding::gap(
                "PROJECT-SCAN-TRUNCATED",
                "Directory entry limit reached",
            ));
            break;
        }
        let full = root.join(&rel);
        if !rel.as_os_str().is_empty() && safe::no_links(&full).is_err() {
            report.findings.push(
                Finding::gap("PROJECT-LINK-EXCLUDED", "Linked directory excluded")
                    .at(&safe::location(&rel)),
            );
            continue;
        }
        let entries = match fs::read_dir(&full) {
            Ok(e) => e,
            Err(_) => {
                report.findings.push(
                    Finding::gap(
                        "PROJECT-READ-FAILED",
                        "Directory unavailable or permission denied",
                    )
                    .at(&safe::location(&rel)),
                );
                continue;
            }
        };
        let mut files = vec![];
        for e in entries {
            walked += 1;
            if walked > max_files {
                report.findings.push(Finding::gap(
                    "PROJECT-SCAN-TRUNCATED",
                    "Directory entry limit reached",
                ));
                break;
            }
            match e {
                Ok(e) => files.push(e),
                Err(_) => report.findings.push(Finding::gap(
                    "PROJECT-READ-FAILED",
                    "Directory entry unavailable",
                )),
            }
        }
        files.sort_by_key(|e| e.file_name());
        for entry in files {
            let child = rel.join(entry.file_name());
            let label = safe::location(&child);
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                report.findings.push(
                    Finding::gap("PROJECT-PATH-ENCODING", "Non-Unicode filename excluded")
                        .at(&label),
                );
                continue;
            };
            let path = child.to_string_lossy().replace('\\', "/");
            let m = match fs::symlink_metadata(entry.path()) {
                Ok(m) => m,
                Err(_) => {
                    report
                        .findings
                        .push(Finding::gap("PROJECT-READ-FAILED", "Entry unavailable").at(&label));
                    continue;
                }
            };
            if safe::is_link(&m) {
                report.findings.push(
                    Finding::gap("PROJECT-LINK-EXCLUDED", "Symlink or reparse point excluded")
                        .at(&label),
                );
                continue;
            }
            if ignores.iter().any(|p| matches(&path, p)) {
                skipped += 1;
                report.findings.push(
                    Finding::new(
                        "PROJECT-EXCLUDED",
                        "Explicit exclusion applied",
                        "unable_to_assess",
                        "review_required",
                    )
                    .at(&label),
                );
                continue;
            }
            if m.is_dir() {
                if excluded.contains(&name) {
                    skipped += 1;
                } else {
                    stack.push(child);
                }
                continue;
            }
            if !m.is_file() {
                report.findings.push(
                    Finding::gap("PROJECT-SPECIAL-EXCLUDED", "Non-regular file excluded")
                        .at(&label),
                );
                continue;
            }
            if name == ".ca-trust-audit-ignore" {
                continue;
            }
            let is_bundle = safe::list(&data.inventory, "ca_bundle_suffixes")
                .iter()
                .any(|s| name.ends_with(s))
                || safe::list(&data.inventory, "ca_bundle_name_hints")
                    .iter()
                    .any(|s| name.contains(s))
                || name.ends_with(".jks");
            let manifests: Vec<_> = safe::array(&data.inventory, "manifests")
                .iter()
                .filter(|e| safe::list(e, "files").iter().any(|p| matches(&path, p)))
                .collect();
            let lock_entries: Vec<_> = safe::array(&data.inventory, "lockfiles")
                .iter()
                .filter(|e| safe::list(e, "files").iter().any(|p| matches(&path, p)))
                .collect();
            let tool = safe::list(&data.inventory, "tool_version_files")
                .iter()
                .any(|p| matches(&path, p));
            let container = safe::list(&data.inventory, "container_files")
                .iter()
                .any(|p| matches(&path, p));
            let ci = safe::list(&data.inventory, "ci_files")
                .iter()
                .any(|p| matches(&path, p));
            let is_text = tool
                || container
                || ci
                || !manifests.is_empty()
                || !lock_entries.is_empty()
                || safe::list(scan, "text_suffixes")
                    .iter()
                    .any(|s| name.ends_with(s))
                || safe::list(scan, "text_filenames").contains(&name);
            if !is_bundle && !is_text {
                continue;
            }
            let b = match safe::project_read(&root, &child, limit) {
                Ok(b) => b,
                Err(_) => {
                    report.findings.push(
                        Finding::gap(
                            "PROJECT-READ-FAILED",
                            "File unavailable, unsafe or oversized",
                        )
                        .at(&label),
                    );
                    continue;
                }
            };
            if is_bundle {
                report
                    .findings
                    .extend(certs::findings(&b, data, &label, false, "PROJECT"));
            }
            if !is_text {
                continue;
            }
            let text = match safe::text(&b) {
                Ok(t) => t,
                Err(_) => {
                    report.findings.push(
                        Finding::gap("PROJECT-TEXT-INVALID", "Invalid UTF-8 file excluded")
                            .at(&label),
                    );
                    continue;
                }
            };
            if serde_json::from_str::<Value>(&text)
                .ok()
                .is_some_and(|v| data.payloads.contains(&v))
            {
                continue;
            }
            report.findings.extend(tls(
                &text,
                &label,
                name.ends_with(".md") || path.starts_with("docs/"),
                &rules,
                "PROJECT",
            ));
            manifest_count += manifests.len();
            locks += lock_entries.len();
            for lock in &lock_entries {
                let kind = if name == "Cargo.lock" {
                    "cargo-lock"
                } else {
                    safe::string(lock, "parser")
                };
                deps += dependencies(kind, &text, &label, data, &mut report);
            }
            if lock_entries.is_empty() {
                if name == "package.json" || name == "go.mod" || tool {
                    deps += dependencies(&name, &text, &label, data, &mut report);
                } else if !manifests.is_empty() {
                    report.findings.push(
                        Finding::gap(
                            "PROJECT-MANIFEST-UNPARSED",
                            "Manifest inventoried without a dependency parser",
                        )
                        .at(&label),
                    );
                }
            }
            if containers && container {
                if !refresh_patterns.iter().any(|r| r.is_match(&text)) {
                    report.findings.push(
                        Finding::gap(
                            "PROJECT-CONTAINER-NO-CA-REFRESH",
                            "Container definition has no recognized CA refresh step",
                        )
                        .at(&label),
                    );
                }
                if text.contains("@sha256:") {
                    report.findings.push(
                        Finding::gap(
                            "PROJECT-CONTAINER-DIGEST-PINNED",
                            "Pinned container digest may preserve stale trust data",
                        )
                        .at(&label),
                    );
                }
            }
            if ci {
                for c in ci_version.captures_iter(&text) {
                    let n = &c[1];
                    for p in safe::array(&data.policy, "packages") {
                        if safe::string(p, "name") == n {
                            report.findings.push(versions::finding(
                                n,
                                &c[2],
                                versions::numeric(&c[2]).is_some_and(|v| v.len() >= 3),
                                p,
                                "PROJECT",
                                &label,
                            ));
                        }
                    }
                }
            }
        }
    }
    // .git is excluded from recursion, but repository-specific TLS configuration still matters.
    if root.join(".git/config").exists() {
        match safe::project_read(&root, Path::new(".git/config"), limit)
            .and_then(|b| safe::text(&b))
        {
            Ok(t) => report.findings.extend(tls(
                &t,
                &safe::location(Path::new(".git/config")),
                false,
                &rules,
                "PROJECT",
            )),
            Err(_) => report.findings.push(Finding::gap(
                "PROJECT-GIT-CONFIG-UNKNOWN",
                "Git configuration unavailable",
            )),
        }
    }
    if manifest_count == 0 && locks == 0 {
        report.findings.push(Finding::gap(
            "PROJECT-NO-MANIFEST",
            "No dependency manifest or lockfile found",
        ));
    }
    if manifest_count > 0 && locks == 0 && deps > 0 {
        report.findings.push(Finding::gap(
            "PROJECT-NO-LOCKFILE",
            "Installed dependency versions are not established by a lockfile",
        ));
    }
    report.findings.push(
        Finding::new(
            "PROJECT-INVENTORY",
            "Static project inventory",
            "not_found",
            "none",
        )
        .evidence("entries visited", &walked.to_string())
        .evidence("directories or files excluded", &skipped.to_string())
        .evidence("dependencies parsed", &deps.to_string()),
    );
    report.notes.push("Paths are opaque SHA-256 references; source lines, raw versions and filenames are withheld. Parsers are partial and never resolve dependencies. Audit a stable local snapshot.".into());
    report.finish();
    Ok(report)
}
