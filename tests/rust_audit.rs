use base64::{Engine, engine::general_purpose::STANDARD};
use emudhra_trust_audit::{
    certs,
    data::Data,
    endpoint,
    model::{Finding, Report},
    parsers, project, safe, versions,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "emudhra-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p.canonicalize().unwrap())
    }
    fn write(&self, name: &str, b: impl AsRef<[u8]>) -> PathBuf {
        let p = self.0.join(name);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, b).unwrap();
        p
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn data() -> Data {
    Data::load(None).unwrap()
}
fn weak() -> Vec<u8> {
    include_bytes!("fixtures/certs/weak-intermediate.pem").to_vec()
}
fn fixture() -> Data {
    let mut d = data();
    d.incident["compromised_intermediates"] =
        json!([{"spki_sha256":certs::parse(&weak()).hashes[0]}]);
    d
}
fn audit(t: &Temp) -> Report {
    project::audit(&t.0, &data(), true).unwrap()
}
fn has(r: &Report, id: &str) -> bool {
    r.findings.iter().any(|f| f.id == id)
}
fn cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_emudhra-trust-audit"))
        .args(args)
        .output()
        .unwrap()
}
fn copy_data(t: &Temp) {
    for name in [
        "checksums.json",
        "incidents/emudhra-2026.json",
        "policies/fixed-versions.json",
        "rules/insecure-tls.json",
        "rules/project-inventory.json",
        "schema/incident-v1.json",
        "schema/policy-v1.json",
        "schema/ruleset-v1.json",
    ] {
        t.write(
            name,
            fs::read(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("data")
                    .join(name),
            )
            .unwrap(),
        );
    }
}

#[test]
fn embedded_data_is_sourced_and_verified() {
    let d = data();
    assert_eq!(
        safe::array(&d.incident, "compromised_intermediates").len(),
        8
    );
    for s in d.sources() {
        assert!(!s["sources"].as_array().unwrap().is_empty());
        assert!(s["data_version"].is_string());
    }
    assert_eq!(project::rules(&d).unwrap().len(), 19);
}
#[test]
fn lf_crlf_cr_have_identical_checksums() {
    for newline in ["\n", "\r\n", "\r"] {
        let t = Temp::new();
        copy_data(&t);
        for p in ["incidents/emudhra-2026.json", "rules/insecure-tls.json"] {
            let b = fs::read(t.0.join(p)).unwrap();
            t.write(p, String::from_utf8(b).unwrap().replace('\n', newline));
        }
        assert!(Data::load(Some(&t.0)).is_ok());
        let mut b = fs::read(t.0.join("incidents/emudhra-2026.json")).unwrap();
        b.push(b' ');
        t.write("incidents/emudhra-2026.json", b);
        assert!(Data::load(Some(&t.0)).is_err());
    }
}
#[test]
fn missing_or_additional_checksum_rejected() {
    let t = Temp::new();
    copy_data(&t);
    let mut v: Value =
        serde_json::from_slice(&fs::read(t.0.join("checksums.json")).unwrap()).unwrap();
    v["files"]["../escape"] = json!("bad");
    t.write("checksums.json", v.to_string());
    assert!(Data::load(Some(&t.0)).is_err());
}
#[test]
fn invalid_schema_rejected_even_with_updated_hashes() {
    let t = Temp::new();
    copy_data(&t);
    let mut v = data().incident;
    v["schema_version"] = json!(99);
    t.write("incidents/emudhra-2026.json", v.to_string());
    t.write("checksums.json", Data::checksums(&t.0).unwrap().to_string());
    assert!(Data::load(Some(&t.0)).is_err());
}
#[test]
fn normalization_retains_non_newline_changes() {
    assert_eq!(safe::normalize(b"a\r\nb\rc\n"), b"a\nb\nc\n");
    assert_ne!(safe::digest(b"{}"), safe::digest(b"{ }"));
}
#[test]
fn certificates_match_exact_spki_without_subject_disclosure() {
    let d = fixture();
    let f = certs::findings(&weak(), &d, "bundle", false, "PROJECT");
    assert!(
        f.iter()
            .any(|f| f.status == "known_indicator" && f.action == "action_required")
    );
    let s = serde_json::to_string(&f).unwrap();
    assert!(!s.contains("Fixture Weak"));
}
#[test]
fn roots_and_unrelated_certs_are_not_exposure() {
    let d = fixture();
    for b in [
        include_bytes!("fixtures/certs/related-root.pem").as_slice(),
        include_bytes!("fixtures/certs/unrelated.pem").as_slice(),
    ] {
        assert!(
            certs::findings(b, &d, "bundle", false, "PROJECT")
                .iter()
                .all(|f| f.action == "none")
        );
    }
}
#[test]
fn malformed_der_never_panics() {
    for len in 0..150 {
        for byte in [0, 0x30, 0xff, 0x80] {
            let b = vec![byte; len];
            assert!(certs::spki(&b).is_err());
        }
    }
}
#[test]
fn partially_invalid_pem_retains_gap() {
    let mut b = weak();
    b.extend_from_slice(b"-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----");
    let f = certs::findings(&b, &fixture(), "bundle", false, "ENDPOINT");
    assert!(f.iter().any(|f| f.status == "known_indicator"));
    assert!(f.iter().any(|f| f.status == "unable_to_assess"));
}
#[test]
fn blocklist_does_not_suppress_independent_store() {
    let d = fixture();
    let mut r = Report::new("test");
    r.findings
        .extend(certs::findings(&weak(), &d, "blocklist", true, "ENDPOINT"));
    r.findings.extend(certs::findings(
        &weak(),
        &d,
        "independent",
        false,
        "ENDPOINT",
    ));
    r.finish();
    assert_eq!(r.verdict, "UNKNOWN");
    assert_eq!(r.exit_code, 2);
}
fn der() -> Vec<u8> {
    let text = String::from_utf8(weak()).unwrap();
    let body = text.split("-----").nth(2).unwrap();
    STANDARD
        .decode(body.split_whitespace().collect::<String>())
        .unwrap()
}
#[test]
fn jks_trusted_entries_parsed() {
    let mut b = vec![];
    b.extend(0xfeedfeedu32.to_be_bytes());
    b.extend(2u32.to_be_bytes());
    b.extend(1u32.to_be_bytes());
    b.extend(2u32.to_be_bytes());
    b.extend(1u16.to_be_bytes());
    b.push(b'a');
    b.extend([0; 8]);
    b.extend(5u16.to_be_bytes());
    b.extend(b"X.509");
    let d = der();
    b.extend((d.len() as u32).to_be_bytes());
    b.extend(d);
    assert_eq!(certs::parse(&b).hashes, certs::parse(&weak()).hashes);
    for n in 0..b.len() {
        assert!(certs::parse(&b[..n]).hashes.is_empty());
    }
}
#[test]
fn windows_store_output_lf_crlf() {
    let cert = STANDARD.encode(der());
    for newline in ["\n", "\r\n"] {
        let text=format!("STORE\tLocalMachine/Root\nSTORE\tLocalMachine/CA\nSTORE\tLocalMachine/Disallowed\nCERT\tLocalMachine/Root\t{cert}\n").replace('\n',newline);
        let f = endpoint::windows_records(text.as_bytes(), &fixture(), false);
        assert!(f.iter().any(|f| f.action == "action_required"));
        assert!(!f.iter().any(|f| f.id == "ENDPOINT-WINDOWS-STORE"));
    }
}
#[test]
fn windows_failure_and_garbage_are_gaps() {
    for b in [
        b"ERROR\tLocalMachine/Root".as_slice(),
        b"SECRET_SENTINEL",
        b"CERT\tLocalMachine/Root\t%%%",
        &[0xff],
    ] {
        let f = endpoint::windows_records(b, &fixture(), false);
        assert!(f.iter().any(|f| f.status == "unable_to_assess"));
        assert!(
            !serde_json::to_string(&f)
                .unwrap()
                .contains("SECRET_SENTINEL")
        );
    }
}
#[test]
fn windows_user_store_switch_is_real() {
    assert!(!endpoint::windows_script(false).contains("CurrentUser"));
    assert!(endpoint::windows_script(true).contains("CurrentUser"));
    assert!(endpoint::windows_script(false).contains("ReadOnly"));
    assert!(
        endpoint::windows_records(b"STORE\tCurrentUser/Root", &data(), false)
            .iter()
            .any(|f| f.status == "unable_to_assess")
    );
}
#[test]
fn network_targets_cannot_inject_shell_or_options() {
    for h in [
        "-option",
        "host;echo",
        "host:65536",
        "https://example.test",
        "foo\nbar",
        "host/SECRET",
        "[::1]:0",
        "",
    ] {
        assert!(endpoint::host(h).is_err());
    }
    assert_eq!(endpoint::host("::1").unwrap().0, "[::1]:443");
    assert!(endpoint::host("example.test").is_ok());
}
#[test]
fn env_values_never_reach_output() {
    let env = BTreeMap::from([
        (
            "HTTPS_PROXY".into(),
            "https://user:SECRET_SENTINEL@host".into(),
        ),
        ("NODE_TLS_REJECT_UNAUTHORIZED".into(), "0".into()),
    ]);
    let f = endpoint::env_findings(&env);
    assert!(f.iter().any(|f| f.action == "action_required"));
    assert!(
        !serde_json::to_string(&f)
            .unwrap()
            .contains("SECRET_SENTINEL")
    );
}
#[test]
fn nonstandard_curl_variable_not_flagged() {
    let f = endpoint::env_findings(&BTreeMap::from([("CURL_INSECURE".into(), "1".into())]));
    assert!(f.iter().all(|f| f.action == "none"));
}
#[test]
fn numeric_comparison_and_branches() {
    use std::cmp::Ordering::*;
    for (a, b, c) in [
        ("2026.09.01", "2026.10.19", Less),
        ("0.13.4", "0.13.10", Less),
        ("24.22.1", "24.9.0", Greater),
        ("v22.23.4", "22.23.4", Equal),
    ] {
        assert_eq!(versions::generic(a, b), Some(c));
    }
    assert!(versions::generic("1.2.3-rc1", "1.2.3").is_none());
    let d = data();
    let p = safe::array(&d.policy, "packages")
        .iter()
        .find(|p| safe::string(p, "name") == "node")
        .unwrap();
    for v in ["20.0.0", "220.0.0", "SECRET", "22.0.0 || 24.0.0"] {
        assert_eq!(
            versions::finding("node", v, true, p, "TEST", "").status,
            "unable_to_assess"
        );
    }
}
#[test]
fn distro_version_ordering() {
    use std::cmp::Ordering::*;
    for (a, b, c) in [
        ("20250419~deb12u1", "20250419~deb12u2", Less),
        ("20250419~deb12u2", "20250419", Less),
        ("20250419", "20250419+deb13u1", Less),
        ("20260816ubuntu0.24.04.1", "20260816", Greater),
        ("1:1.0-1", "2:0.9-1", Less),
        ("2026.2.92_v9.0.319", "2026.2.93_v9.0.320", Less),
    ] {
        assert_eq!(versions::dpkg(a, b), Some(c));
        assert_eq!(versions::dpkg(b, a), Some(c.reverse()));
    }
}
#[test]
fn all_supported_lock_parsers() {
    for (kind, text, name) in [
        (
            "npm-lock",
            r#"{"packages":{"node_modules/node":{"version":"22.0.0"}}}"#,
            "node",
        ),
        (
            "npm-lock",
            r#"{"dependencies":{"node":{"version":"22.0.0","dependencies":{"uv":{"version":"1.0.0"}}}}}"#,
            "node",
        ),
        (
            "package.json",
            r#"{"dependencies":{"node":"22.0.0"}}"#,
            "node",
        ),
        ("requirements", "certifi==2024.1.1\n", "certifi"),
        (
            "cargo-lock",
            "[[package]]\nname = \"webpki-roots\"\nversion = \"1.0.1\"\n",
            "webpki-roots",
        ),
        (
            "toml-lock",
            "[[package]]\nname = \"certifi\"\nversion = \"2024.1.1\"\n",
            "certifi",
        ),
        (
            "pipfile-lock",
            r#"{"default":{"certifi":{"version":"==2024.1.1"}}}"#,
            "certifi",
        ),
        (
            "composer-lock",
            r#"{"packages":[{"name":"composer/ca-bundle","version":"1.0.0"}]}"#,
            "composer/ca-bundle",
        ),
        ("yarn-lock", "node@^22:\n  version \"22.0.0\"\n", "node"),
        ("pnpm-lock", "packages:\n  node@22.0.0:\n", "node"),
        ("gemfile-lock", "    certifi (1.0.0)\n", "certifi"),
        (
            "gosum",
            "example.test/pkg v1.0.0 h1:hash\n",
            "example.test/pkg",
        ),
        (
            "mix-lock",
            r#""castore": {:hex, :castore, "1.0.0"}"#,
            "castore",
        ),
        ("go.mod", "toolchain go1.27.0\n", "go"),
        (".tool-versions", "nodejs 22.0.0\n", "node"),
        ("mise.toml", "[tools]\nnode = \"22.0.0\"\n", "node"),
    ] {
        let d = parsers::parse(kind, text).unwrap();
        assert!(d.iter().any(|d| d.name == name), "{kind}");
    }
}
#[test]
fn malformed_lock_shapes_are_not_panics() {
    for kind in ["npm-lock", "pipfile-lock", "composer-lock", "package.json"] {
        for text in ["[]", "null", "{broken", r#"{"default":[],"packages":123}"#] {
            let _ = parsers::parse(kind, text);
        }
    }
}
#[test]
fn manifest_range_is_not_pin() {
    assert!(
        !parsers::parse(
            "package.json",
            r#"{"dependencies":{"node":"22.0.0 || 24.0.0"}}"#
        )
        .unwrap()[0]
            .pinned
    );
}
#[test]
fn every_tool_pin_reaches_policy() {
    for (name, text) in [
        (".nvmrc", "22.0.0"),
        (".node-version", "22.0.0"),
        (".go-version", "1.27.0"),
        (".tool-versions", "nodejs 22.0.0"),
        ("mise.toml", "[tools]\nnode = \"22.0.0\""),
    ] {
        let t = Temp::new();
        t.write(name, text);
        assert!(has(&audit(&t), "PROJECT-DEPENDENCY-OUTDATED"), "{name}");
    }
}
#[test]
fn multiple_dependency_versions_remain_checked() {
    let t = Temp::new();
    t.write("one/requirements.txt", "certifi==2026.10.19");
    t.write("two/requirements.txt", "certifi==2024.1.1");
    let r = audit(&t);
    assert!(has(&r, "PROJECT-DEPENDENCY-OUTDATED"));
    assert!(has(&r, "PROJECT-DEPENDENCY-CURRENT"));
}
#[test]
fn unsupported_manifest_and_lock_are_gaps() {
    let t = Temp::new();
    t.write("pom.xml", "<project/>");
    t.write("bun.lockb", "opaque");
    let r = audit(&t);
    assert!(has(&r, "PROJECT-MANIFEST-UNPARSED"));
    assert!(has(&r, "PROJECT-DEPENDENCY-COVERAGE"));
}
#[test]
fn fake_data_id_does_not_bypass_rules() {
    let t = Temp::new();
    t.write(
        "config.json",
        json!({"ruleset_id":"insecure-tls-settings","code":"verify=False"}).to_string(),
    );
    assert!(has(&audit(&t), "PROJECT-TLS-VERIFY-PYTHON-REQUESTS"));
}
#[test]
fn actual_data_files_are_not_tls_findings() {
    let t = Temp::new();
    t.write("rules.json", serde_json::to_vec(&data().rules).unwrap());
    assert!(
        !audit(&t)
            .findings
            .iter()
            .any(|f| f.id.starts_with("PROJECT-TLS-"))
    );
}
#[test]
fn secrets_in_content_paths_versions_and_ci_are_withheld() {
    let t = Temp::new();
    t.write(
        "SECRET_FILENAME.py",
        "requests.get(url,verify=False,headers={'Authorization':'SECRET_VALUE'})",
    );
    t.write(
        "package-lock.json",
        r#"{"packages":{"node_modules/node":{"version":"https://user:SECRET_VERSION@host/pkg"}}}"#,
    );
    t.write(".github/workflows/test.yml", "node-version: 22SECRET_CI\n");
    let s = serde_json::to_string(&audit(&t)).unwrap();
    assert!(!s.contains("SECRET"));
    assert!(!s.contains(t.0.to_str().unwrap()));
}
#[test]
fn docs_are_not_production_assertions() {
    let t = Temp::new();
    t.write("README.md", "NODE_TLS_REJECT_UNAUTHORIZED=0");
    let r = audit(&t);
    let f = r
        .findings
        .iter()
        .find(|f| f.id == "PROJECT-TLS-VERIFY-NODE-ENV")
        .unwrap();
    assert_eq!(f.status, "suspicious");
    assert_ne!(r.verdict, "INSECURE");
}
#[test]
fn plaintext_loopback_exception_has_boundaries() {
    let d = data();
    let rules = project::rules(&d).unwrap();
    for host in ["localhost", "127.0.0.1", "[::1]", "localhost:8080"] {
        assert!(
            !project::tls(
                &format!("registry=http://{host}"),
                "test",
                false,
                &rules,
                "PROJECT"
            )
            .iter()
            .any(|f| f.id == "PROJECT-TLS-PLAINTEXT-REPOSITORY")
        );
    }
    assert!(
        project::tls(
            "registry=http://localhost.attacker.test",
            "test",
            false,
            &rules,
            "PROJECT"
        )
        .iter()
        .any(|f| f.id == "PROJECT-TLS-PLAINTEXT-REPOSITORY")
    );
}
#[test]
fn traversal_absolute_and_parent_paths_rejected() {
    let t = Temp::new();
    t.write("a.txt", "safe");
    for path in [
        PathBuf::from("../secret"),
        t.0.join("a.txt"),
        PathBuf::from("a/../a.txt"),
    ] {
        assert!(safe::project_read(&t.0, &path, 100).is_err());
    }
}
#[test]
fn invalid_utf8_and_large_files_are_gaps() {
    let t = Temp::new();
    t.write("bad.rs", [0xff, 0xfe]);
    t.write("big.rs", vec![b'x'; 1_048_577]);
    let r = audit(&t);
    assert!(has(&r, "PROJECT-TEXT-INVALID"));
    assert!(has(&r, "PROJECT-READ-FAILED"));
}
#[test]
fn exclusions_reported_and_bounded() {
    let t = Temp::new();
    t.write("client.rs", "danger_accept_invalid_certs(true)");
    t.write(".ca-trust-audit-ignore", "client.rs");
    let r = audit(&t);
    assert!(has(&r, "PROJECT-EXCLUDED"));
    assert!(!has(&r, "PROJECT-TLS-VERIFY-RUST-DANGER"));
    t.write(".ca-trust-audit-ignore", vec![b'x'; 65537]);
    assert!(has(&audit(&t), "PROJECT-IGNORE-UNREADABLE"));
}
#[test]
fn git_config_audited_without_recursing_git() {
    let t = Temp::new();
    t.write(".git/config", "sslVerify=false");
    t.write(".git/objects/secret.rs", "verify=False");
    let r = audit(&t);
    assert!(has(&r, "PROJECT-TLS-VERIFY-GIT-CONFIG"));
    assert!(!has(&r, "PROJECT-TLS-VERIFY-PYTHON-REQUESTS"));
}
#[cfg(unix)]
#[test]
fn symlink_and_fifo_do_not_get_read() {
    use std::os::unix::fs::symlink;
    let t = Temp::new();
    let outside = Temp::new();
    outside.write("secret", "SECRET");
    symlink(outside.0.join("secret"), t.0.join("client.rs")).unwrap();
    symlink(&outside.0, t.0.join("dir")).unwrap();
    assert!(safe::project_read(&t.0, Path::new("client.rs"), 100).is_err());
    assert!(has(&audit(&t), "PROJECT-LINK-EXCLUDED"));
    let status = Command::new("mkfifo")
        .arg(t.0.join("pipe.rs"))
        .status()
        .unwrap();
    assert!(status.success());
    assert!(safe::read(&t.0.join("pipe.rs"), 100, false).is_err());
    assert!(has(&audit(&t), "PROJECT-SPECIAL-EXCLUDED"));
}
#[cfg(unix)]
#[test]
fn permission_failure_is_not_pass() {
    use std::os::unix::fs::PermissionsExt;
    let t = Temp::new();
    let p = t.write("private.rs", "verify=False");
    fs::set_permissions(&p, fs::Permissions::from_mode(0o0)).unwrap();
    if fs::read(&p).is_err() {
        assert!(has(&audit(&t), "PROJECT-READ-FAILED"));
    }
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
}
#[test]
fn file_limit_reports_gap() {
    let t = Temp::new();
    for i in 0..5 {
        t.write(&format!("{i}.rs"), "");
    }
    let mut d = data();
    d.rules["scan"]["max_files"] = json!(2);
    let r = project::audit(&t.0, &d, true).unwrap();
    assert!(has(&r, "PROJECT-SCAN-TRUNCATED"));
}
#[test]
fn output_codes_and_no_effective_trust_claims() {
    let mut r = Report::new("test");
    r.findings.push(Finding::gap("TEST", "unknown"));
    r.finish();
    assert_eq!(r.exit_code, 1);
    r.findings.push(Finding::new(
        "TEST",
        "match",
        "known_indicator",
        "action_required",
    ));
    r.finish();
    assert_eq!(r.exit_code, 2);
    r.errors.push("failure".into());
    r.finish();
    assert_eq!(r.exit_code, 3);
    assert_ne!(r.verdict, "EXPOSED");
    assert_ne!(r.verdict, "BLOCKED");
}
#[test]
fn standalone_binary_needs_no_checkout_or_runtime() {
    let t = Temp::new();
    let p = t.0.join(if cfg!(windows) { "audit.exe" } else { "audit" });
    fs::copy(env!("CARGO_BIN_EXE_emudhra-trust-audit"), &p).unwrap();
    let out = Command::new(p)
        .args(["data", "--verify"])
        .current_dir(&t.0)
        .env("PATH", "")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&out.stdout).unwrap()["checksum_status"],
        "verified"
    );
}
#[test]
fn cli_default_does_not_run_tools_or_modify_project() {
    let t = Temp::new();
    t.write("client.rs", "verify=False");
    let before = fs::read(t.0.join("client.rs")).unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_emudhra-trust-audit"))
        .args(["project", t.0.to_str().unwrap()])
        .env("PATH", "")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert_eq!(before, fs::read(t.0.join("client.rs")).unwrap());
    assert_eq!(fs::read_dir(&t.0).unwrap().count(), 1);
}
#[test]
fn endpoint_fsroot_cannot_probe_installed_tools() {
    let t = Temp::new();
    let o = cli(&["endpoint", "--commands", "--fs-root", t.0.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1));
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert!(
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["id"] == "ENDPOINT-EXECUTABLE-PROBES-DISABLED")
    );
}
#[test]
fn cli_errors_never_echo_arguments() {
    for args in [
        vec!["project", "ABSENT_SECRET"],
        vec!["--SECRET"],
        vec!["endpoint", "--network-test", "host;SECRET"],
    ] {
        let o = cli(&args);
        assert_eq!(o.status.code(), Some(3));
        assert!(!String::from_utf8_lossy(&o.stdout).contains("SECRET"));
        assert!(serde_json::from_slice::<Value>(&o.stdout).is_ok());
    }
}
#[test]
fn output_never_overwrites_existing_file() {
    let t = Temp::new();
    let p = t.write("saved", "keep");
    let o = cli(&["data", "--output", p.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(3));
    assert_eq!(fs::read(p).unwrap(), b"keep");
}
#[test]
fn sarif_and_text_outputs_are_supported() {
    let t = Temp::new();
    t.write("client.go", "InsecureSkipVerify: true");
    let o = cli(&["project", t.0.to_str().unwrap(), "--format", "sarif"]);
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["version"], "2.1.0");
    assert_eq!(
        v["runs"][0]["tool"]["driver"]["name"],
        "emudhra-trust-audit"
    );
    let o = cli(&["project", t.0.to_str().unwrap(), "--format", "text"]);
    assert!(String::from_utf8_lossy(&o.stdout).contains("INSECURE"));
}

#[test]
fn windows_policy_readonly_results() {
    for newline in ["\n", "\r\n"] {
        assert_eq!(
            endpoint::windows_policy_records(&format!("DisableRootAutoUpdate=1{newline}"))[0]
                .action,
            "action_required"
        );
        assert_eq!(
            endpoint::windows_policy_records(&format!(
                "DisableRootAutoUpdate=0{newline}DisallowedCtlPresent=True{newline}"
            ))[0]
                .status,
            "not_found"
        );
    }
    assert_eq!(
        endpoint::windows_policy_records("SECRET_VALUE")[0].status,
        "unable_to_assess"
    );
}

#[cfg(windows)]
#[test]
fn windows_reparse_and_file_id() {
    use std::os::windows::fs::symlink_dir;
    assert_eq!(
        safe::location(Path::new("a/b")),
        safe::location(Path::new("a\\b"))
    );
    let t = Temp::new();
    let regular = t.write("regular.txt", "regular");
    // Temp uses canonicalize: Windows returns a verbatim drive prefix.
    assert_eq!(safe::read(&regular, 100, false).unwrap(), b"regular");
    assert_eq!(
        safe::project_read(&t.0, Path::new("regular.txt"), 100).unwrap(),
        b"regular"
    );
    let outside = Temp::new();
    outside.write("secret.rs", "SECRET");
    if symlink_dir(&outside.0, t.0.join("linked")).is_ok() {
        assert!(has(&audit(&t), "PROJECT-LINK-EXCLUDED"));
        assert!(safe::project_read(&t.0, Path::new("linked/secret.rs"), 100).is_err());
    }
}

#[test]
fn certifi_environment_inspected_without_interpreter() {
    let t = Temp::new();
    t.write("Lib/site-packages/certifi/cacert.pem", weak());
    t.write(
        "Lib/site-packages/certifi-2024.1.1.dist-info/METADATA",
        "Name: certifi\r\nVersion: 2024.1.1\r\n",
    );
    let findings = endpoint::certifi_environment(&t.0, &fixture());
    assert!(findings.iter().any(|f| f.id == "ENDPOINT-SPKI-PRESENT"));
    assert!(
        findings
            .iter()
            .any(|f| f.id == "ENDPOINT-DEPENDENCY-OUTDATED")
    );
}
