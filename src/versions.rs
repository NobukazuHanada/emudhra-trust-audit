use crate::{model::Finding, safe};
use regex::Regex;
use serde_json::Value;
use std::cmp::Ordering;
pub fn numeric(v: &str) -> Option<Vec<u64>> {
    let v = v.trim().trim_start_matches(['v', 'V']);
    if !Regex::new(r"^[0-9]+(?:\.[0-9]+)*$")
        .expect("static regex")
        .is_match(v)
    {
        return None;
    }
    v.split('.').map(|p| p.parse().ok()).collect()
}
pub fn generic(a: &str, b: &str) -> Option<Ordering> {
    let mut a = numeric(a)?;
    let mut b = numeric(b)?;
    let n = a.len().max(b.len());
    a.resize(n, 0);
    b.resize(n, 0);
    Some(a.cmp(&b))
}
fn order(c: Option<u8>) -> i32 {
    match c {
        Some(b'~') => -1,
        None => 0,
        Some(c) if c.is_ascii_digit() => 0,
        Some(c) if c.is_ascii_alphabetic() => c as i32,
        Some(c) => c as i32 + 256,
    }
}
fn part(a: &[u8], b: &[u8]) -> Ordering {
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        while a.get(i).is_some_and(|c| !c.is_ascii_digit())
            || b.get(j).is_some_and(|c| !c.is_ascii_digit())
        {
            let cmp = order(a.get(i).copied()).cmp(&order(b.get(j).copied()));
            if cmp != Ordering::Equal {
                return cmp;
            }
            if i < a.len() {
                i += 1;
            }
            if j < b.len() {
                j += 1;
            }
        }
        while a.get(i) == Some(&b'0') {
            i += 1;
        }
        while b.get(j) == Some(&b'0') {
            j += 1;
        }
        let (ai, bj) = (i, j);
        while a.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        while b.get(j).is_some_and(u8::is_ascii_digit) {
            j += 1;
        }
        let cmp = (i - ai)
            .cmp(&(j - bj))
            .then_with(|| a[ai..i].cmp(&b[bj..j]));
        if cmp != Ordering::Equal {
            return cmp;
        }
    }
    Ordering::Equal
}
pub fn dpkg(a: &str, b: &str) -> Option<Ordering> {
    fn split(v: &str) -> Option<(u64, &str, &str)> {
        if !Regex::new(r"^[0-9][0-9A-Za-z.+_:~\-]*$").ok()?.is_match(v) {
            return None;
        }
        let (e, v) = if let Some((e, v)) = v.split_once(':') {
            (e.parse().ok()?, v)
        } else {
            (0, v)
        };
        let (u, r) = v.rsplit_once('-').unwrap_or((v, ""));
        Some((e, u, r))
    }
    let (ae, au, ar) = split(a)?;
    let (be, bu, br) = split(b)?;
    Some(
        ae.cmp(&be)
            .then_with(|| part(au.as_bytes(), bu.as_bytes()))
            .then_with(|| part(ar.as_bytes(), br.as_bytes())),
    )
}
pub fn finding(
    name: &str,
    version: &str,
    pinned: bool,
    policy: &Value,
    scope: &str,
    location: &str,
) -> Finding {
    let branch = safe::array(policy, "branches").iter().find(|b| {
        let m = safe::string(b, "match");
        m == "*"
            || version.trim_start_matches('v') == m
            || version
                .trim_start_matches('v')
                .starts_with(&format!("{m}."))
    });
    let fixed = branch
        .map(|b| safe::string(b, "fixed"))
        .unwrap_or_else(|| safe::string(policy, "fixed_version"));
    let compared = if !pinned {
        None
    } else if safe::string(policy, "scheme") == "dpkg" {
        dpkg(version, fixed)
    } else {
        generic(version, fixed)
    };
    let (suffix, status, action, title) = match compared {
        Some(Ordering::Less) => (
            "OUTDATED",
            "known_indicator",
            "action_required",
            "Predates the recorded fix; version evidence only",
        ),
        Some(_) => (
            "CURRENT",
            "not_found",
            "none",
            "At or above the recorded fix; installed state may differ",
        ),
        None => (
            "UNKNOWN",
            "unable_to_assess",
            "review_required",
            "Version is a range, unknown branch or otherwise uncomparable",
        ),
    };
    let mut f = Finding::new(
        &format!("{scope}-DEPENDENCY-{suffix}"),
        title,
        status,
        action,
    )
    .evidence("component", name)
    .at(location);
    // Only recognized numeric versions, or restricted package-manager versions, reach output.
    if numeric(version).is_some() {
        f = f.evidence("version", version);
    }
    if !fixed.is_empty() {
        f = f.evidence("recorded fixed version", fixed);
    }
    f.references = safe::list(policy, "sources");
    f.confidence = "medium".into();
    if suffix == "OUTDATED" {
        f.tags.push("outdated-trust-component".into());
    }
    if action != "none" {
        f.remediation=vec!["Check the vendor's current advisory, update the component and independent CA bundles, then rebuild and restart affected processes.".into()];
    }
    f
}
