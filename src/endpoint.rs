use crate::{
    certs,
    data::Data,
    model::{Finding, Report},
    project, safe, versions,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use regex::Regex;
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

pub struct Options {
    pub commands: bool,
    pub user_stores: bool,
    pub root: Option<PathBuf>,
    pub bundles: Vec<PathBuf>,
    pub network: Option<String>,
}
const OVERRIDES: &[&str] = &[
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "AWS_CA_BUNDLE",
    "PIP_CERT",
    "NODE_EXTRA_CA_CERTS",
    "GIT_SSL_CAINFO",
    "CARGO_HTTP_CAINFO",
    "DENO_CERT",
    "NIX_SSL_CERT_FILE",
];
fn mapped(root: Option<&Path>, path: &Path) -> PathBuf {
    if let Some(root) = root {
        root.join(
            path.components()
                .filter_map(|c| {
                    if let std::path::Component::Normal(s) = c {
                        Some(s)
                    } else {
                        None
                    }
                })
                .collect::<PathBuf>(),
        )
    } else {
        path.to_owned()
    }
}
// No shell; only fixed argument vectors. Output is bounded during capture, errors never echo raw text.
pub fn probe(exe: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let mut child = Command::new(exe)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "probe unavailable")?;
    let mut pipe = child.stdout.take().ok_or("probe output unavailable")?;
    let exceeded = Arc::new(AtomicBool::new(false));
    let flag = exceeded.clone();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut b = vec![];
        let result = pipe.by_ref().take(16_777_217).read_to_end(&mut b);
        if b.len() > 16_777_216 {
            flag.store(true, Ordering::Relaxed);
        }
        let _ = tx.send((result.is_ok(), b));
    });
    let start = Instant::now();
    loop {
        if exceeded.load(Ordering::Relaxed) || start.elapsed() > Duration::from_secs(10) {
            let _ = child.kill();
            let _ = child.wait();
            return Err("probe timed out or output exceeded limit".into());
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return Err("probe failed".into());
                }
                break;
            }
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("probe wait failed".into());
            }
        }
    }
    let (ok, b) = rx
        .recv_timeout(Duration::from_millis(500))
        .map_err(|_| "probe output incomplete")?;
    if !ok || b.len() > 16_777_216 {
        return Err("probe output incomplete".into());
    }
    Ok(b)
}
fn executable(name: &str) -> Option<PathBuf> {
    for dir in std::env::split_paths(&std::env::var_os("PATH")?) {
        if !dir.is_absolute() {
            continue;
        }
        let path = dir.join(if cfg!(windows) {
            format!("{name}.exe")
        } else {
            name.into()
        });
        if path.is_file() {
            return Some(path);
        }
    }
    None
}
fn source(path: &Path, label: &str, data: &Data, report: &mut Report, follow: bool) {
    match fs::metadata(path) {
        Ok(m) if m.is_dir() => {
            let entries = match fs::read_dir(path) {
                Ok(e) => e,
                Err(_) => {
                    report.findings.push(
                        Finding::gap(
                            "ENDPOINT-STORE-UNREADABLE",
                            "Certificate directory unavailable",
                        )
                        .at(label),
                    );
                    return;
                }
            };
            let mut count = 0;
            for e in entries {
                count += 1;
                if count > 4096 {
                    report.findings.push(
                        Finding::gap(
                            "ENDPOINT-STORE-LIMIT",
                            "Certificate directory limit reached",
                        )
                        .at(label),
                    );
                    break;
                }
                match e {
                    Ok(e) => {
                        if e.path().is_dir() {
                            continue;
                        }
                        read_source(&e.path(), label, data, report, follow);
                    }
                    Err(_) => report.findings.push(
                        Finding::gap("ENDPOINT-STORE-UNREADABLE", "Certificate entry unavailable")
                            .at(label),
                    ),
                }
            }
            if count == 0 {
                report.findings.push(
                    Finding::gap("ENDPOINT-STORE-EMPTY", "Certificate directory empty").at(label),
                );
            }
        }
        _ => read_source(path, label, data, report, follow),
    }
}
fn read_source(path: &Path, label: &str, data: &Data, report: &mut Report, follow: bool) {
    match safe::read(path, 16_777_216, follow) {
        Ok(b) => report
            .findings
            .extend(certs::findings(&b, data, label, false, "ENDPOINT")),
        Err(_) => report.findings.push(
            Finding::gap(
                "ENDPOINT-STORE-UNREADABLE",
                "Certificate source unavailable, unsafe or oversized",
            )
            .at(label),
        ),
    }
}
pub fn windows_script(user: bool) -> String {
    let scopes = if user {
        "@('LocalMachine','CurrentUser')"
    } else {
        "@('LocalMachine')"
    };
    format!(
        r#"[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); $ErrorActionPreference='Stop'; foreach($scope in {scopes}) {{ foreach($name in @('Root','CA','Disallowed')) {{ $store=$null; try {{ $store=[System.Security.Cryptography.X509Certificates.X509Store]::new($name,[System.Security.Cryptography.X509Certificates.StoreLocation]::$scope); $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor [System.Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly); Write-Output ('STORE'+"`t"+$scope+'/'+$name); foreach($cert in $store.Certificates) {{ Write-Output ('CERT'+"`t"+$scope+'/'+$name+"`t"+[Convert]::ToBase64String($cert.RawData)) }} }} catch {{ Write-Output ('ERROR'+"`t"+$scope+'/'+$name) }} finally {{ if($null -ne $store) {{$store.Close()}} }} }} }}"#
    )
}
pub fn windows_records(bytes: &[u8], data: &Data, user: bool) -> Vec<Finding> {
    let Ok(text) = safe::text(bytes) else {
        return vec![Finding::gap(
            "ENDPOINT-WINDOWS-STORE",
            "Windows store output could not be parsed",
        )];
    };
    let mut out = vec![];
    let mut stores = std::collections::BTreeSet::new();
    for line in text.trim_start_matches('\u{feff}').lines() {
        let parts: Vec<_> = line.split('\t').collect();
        if parts.len() < 2 {
            out.push(Finding::gap(
                "ENDPOINT-WINDOWS-STORE",
                "Unexpected Windows store record",
            ));
            continue;
        }
        let label = parts[1];
        if ![
            "LocalMachine/Root",
            "LocalMachine/CA",
            "LocalMachine/Disallowed",
            "CurrentUser/Root",
            "CurrentUser/CA",
            "CurrentUser/Disallowed",
        ]
        .contains(&label)
            || (!user && label.starts_with("CurrentUser/"))
        {
            out.push(Finding::gap(
                "ENDPOINT-WINDOWS-STORE",
                "Unexpected Windows store scope",
            ));
            continue;
        }
        match parts[0] {
            "STORE" => {
                stores.insert(label);
            }
            "CERT" if parts.len() == 3 => match STANDARD.decode(parts[2]) {
                Ok(b) => out.extend(certs::findings(
                    &b,
                    data,
                    label,
                    label.ends_with("/Disallowed"),
                    "ENDPOINT",
                )),
                Err(_) => out.push(
                    Finding::gap("ENDPOINT-WINDOWS-STORE", "Invalid certificate record").at(label),
                ),
            },
            _ => out.push(
                Finding::gap(
                    "ENDPOINT-WINDOWS-STORE",
                    "Windows store enumeration incomplete",
                )
                .at(label),
            ),
        }
    }
    if stores.len() != if user { 6 } else { 3 } {
        out.push(Finding::gap(
            "ENDPOINT-WINDOWS-STORE",
            "Not all requested Windows stores were enumerated",
        ));
    }
    if out.is_empty() {
        out.push(Finding::gap(
            "ENDPOINT-WINDOWS-STORE",
            "Requested stores contained no certificates",
        ));
    }
    out
}
pub fn windows_policy_records(text: &str) -> Vec<Finding> {
    let lines = text.lines().map(str::trim).collect::<Vec<_>>();
    if lines.contains(&"DisableRootAutoUpdate=1") {
        let mut f = Finding::new(
            "ENDPOINT-WINDOWS-CTL-DISABLED",
            "Automatic Windows root updates are disabled",
            "known_indicator",
            "action_required",
        );
        f.remediation.push("Review the enterprise trust-update policy under change control; confirm how disallowed CTLs are deployed. Do not change the registry during this audit.".into());
        vec![f]
    } else if lines.contains(&"DisableRootAutoUpdate=0")
        && lines.contains(&"DisallowedCtlPresent=True")
    {
        vec![Finding::new(
            "ENDPOINT-WINDOWS-CTL-CONFIGURED",
            "Update policy and local disallowed CTL are present; freshness is not established",
            "not_found",
            "none",
        )]
    } else {
        vec![Finding::gap(
            "ENDPOINT-WINDOWS-CTL-UNKNOWN",
            "Windows trust-update policy or disallowed CTL could not be established",
        )]
    }
}

pub fn host(input: &str) -> Result<(String, String), String> {
    if input.len() > 253 || input.is_empty() || input.starts_with('-') {
        return Err("invalid network target".into());
    }
    if let Ok(ip) = input.parse::<std::net::IpAddr>() {
        return Ok((
            if ip.is_ipv6() {
                format!("[{ip}]:443")
            } else {
                format!("{ip}:443")
            },
            ip.to_string(),
        ));
    }
    if !input.split('.').all(|p| {
        !p.is_empty()
            && p.len() <= 63
            && !p.starts_with('-')
            && !p.ends_with('-')
            && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }) {
        return Err("invalid network target".into());
    }
    Ok((format!("{input}:443"), input.into()))
}
pub fn env_findings(env: &BTreeMap<String, String>) -> Vec<Finding> {
    let mut out = vec![];
    for (name, values) in [
        ("GIT_SSL_NO_VERIFY", &["1", "true", "yes", "on"][..]),
        ("NODE_TLS_REJECT_UNAUTHORIZED", &["0"][..]),
        ("PYTHONHTTPSVERIFY", &["0"][..]),
    ] {
        if env
            .get(name)
            .is_some_and(|v| values.contains(&v.trim().to_lowercase().as_str()))
        {
            let mut f = Finding::new(
                "ENDPOINT-VERIFICATION-DISABLED-ENV",
                "Environment disables TLS certificate verification",
                "known_indicator",
                "action_required",
            )
            .evidence("variable", name);
            f.tags.push("tls-verification-disabled".into());
            f.remediation.push(
                "Remove the disabling variable; configure the intended private CA instead.".into(),
            );
            out.push(f);
        }
    }
    if out.is_empty() {
        out.push(Finding::new(
            "ENDPOINT-VERIFICATION-ENV-CLEAN",
            "No recognized TLS-disabling environment setting",
            "not_found",
            "none",
        ));
    }
    for name in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "http_proxy",
        "https_proxy",
        "ALL_PROXY",
        "NO_PROXY",
    ] {
        if env.contains_key(name) {
            out.push(
                Finding::new(
                    "ENDPOINT-PROXY-CONFIGURED",
                    "Proxy configuration may change observed trust",
                    "known_indicator",
                    "none",
                )
                .evidence("variable", name),
            );
        }
    }
    out
}
pub fn certifi_environment(prefix: &Path, data: &Data) -> Vec<Finding> {
    let mut r = Report::new("endpoint");
    let mut sites = vec![prefix.join("Lib/site-packages")];
    if let Ok(entries) = fs::read_dir(prefix.join("lib")) {
        for entry in entries.take(64).flatten() {
            if entry.file_name().to_string_lossy().starts_with("python") {
                sites.push(entry.path().join("site-packages"));
            }
        }
    }
    let mut found = false;
    for site in sites {
        let bundle = site.join("certifi/cacert.pem");
        if bundle.exists() {
            found = true;
            source(
                &bundle,
                "active environment certifi bundle",
                data,
                &mut r,
                true,
            );
        }
        if let Ok(entries) = fs::read_dir(&site) {
            for entry in entries.take(1024).flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.starts_with("certifi-")
                    && name.ends_with(".dist-info")
                    && let Ok(text) = safe::read(&entry.path().join("METADATA"), 1_048_576, false)
                        .and_then(|b| safe::text(&b))
                    && let Some(v) = text.lines().find_map(|l| l.strip_prefix("Version: "))
                {
                    for p in safe::array(&data.policy, "packages") {
                        if safe::string(p, "name") == "certifi" {
                            r.findings.push(versions::finding(
                                "certifi",
                                v,
                                true,
                                p,
                                "ENDPOINT",
                                "active environment metadata",
                            ));
                        }
                    }
                }
            }
        }
    }
    if !found {
        r.findings.push(Finding::gap(
            "ENDPOINT-CERTIFI-UNKNOWN",
            "Active environment has no readable conventional certifi bundle",
        ));
    }
    r.findings
}

pub fn audit(opts: &Options, data: &Data) -> Result<Report, String> {
    if let Some(h) = &opts.network {
        host(h)?;
    }
    let mut r = Report::new("endpoint");
    r.data_sources = data.sources();
    let root = opts.root.as_deref();
    let env: BTreeMap<String, String> = if root.is_some() {
        BTreeMap::new()
    } else {
        std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .collect()
    };
    r.findings.extend(env_findings(&env));
    for name in OVERRIDES {
        if let Some(raw) = env.get(*name).filter(|s| !s.is_empty()) {
            r.findings.push(
                Finding::new(
                    "ENDPOINT-CA-OVERRIDE-ENV",
                    "Client uses a custom CA source",
                    "known_indicator",
                    "review_required",
                )
                .evidence("variable", name),
            );
            source(Path::new(raw), name, data, &mut r, true);
        }
    }
    let candidates = if cfg!(target_os = "macos") {
        vec![
            "/etc/ssl/cert.pem",
            "/opt/homebrew/etc/ca-certificates/cert.pem",
            "/usr/local/etc/ca-certificates/cert.pem",
        ]
    } else if cfg!(windows) {
        vec![]
    } else {
        vec![
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/cert.pem",
            "/etc/ssl/ca-bundle.pem",
            "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        ]
    };
    let mut found = false;
    for path in candidates {
        let p = mapped(root, Path::new(path));
        if fs::symlink_metadata(&p).is_ok() {
            found = true;
            source(&p, "system CA bundle", data, &mut r, true);
        }
    }
    for p in &opts.bundles {
        source(p, "explicit CA source", data, &mut r, false);
    }
    if !found && !cfg!(windows) {
        r.findings.push(Finding::gap(
            "ENDPOINT-SYSTEM-BUNDLE",
            "No readable conventional system CA bundle located",
        ));
    }
    if let Some(home) = env.get("JAVA_HOME") {
        for suffix in ["lib/security/cacerts", "jre/lib/security/cacerts"] {
            let p = Path::new(home).join(suffix);
            if p.exists() {
                source(&p, "JAVA_HOME cacerts", data, &mut r, true);
            }
        }
    }
    for name in ["VIRTUAL_ENV", "CONDA_PREFIX"] {
        if let Some(prefix) = env.get(name) {
            r.findings
                .extend(certifi_environment(Path::new(prefix), data));
        }
    }
    let rules = project::rules(data)?;
    let mut configs = vec![mapped(root, Path::new("/etc/gitconfig"))];
    if opts.user_stores
        && let Some(home) = env.get(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
    {
        for file in [
            ".gitconfig",
            ".npmrc",
            ".curlrc",
            ".config/pip/pip.conf",
            "pip/pip.ini",
            ".cargo/config.toml",
        ] {
            configs.push(Path::new(home).join(file));
        }
    }
    for p in configs {
        if p.exists() {
            match safe::read(&p, 1_048_576, false).and_then(|b| safe::text(&b)) {
                Ok(t) => r.findings.extend(project::tls(
                    &t,
                    "local client configuration",
                    false,
                    &rules,
                    "ENDPOINT",
                )),
                Err(_) => r.findings.push(Finding::gap(
                    "ENDPOINT-CONFIG-UNREADABLE",
                    "Client configuration unavailable",
                )),
            }
        }
    }
    if mapped(root, Path::new("/.dockerenv")).exists()
        || mapped(root, Path::new("/run/.containerenv")).exists()
    {
        r.findings.push(Finding::gap(
            "ENDPOINT-CONTAINER-CONTEXT",
            "Container result does not describe the host; audit and update both",
        ));
    }
    if env.contains_key("WSL_DISTRO_NAME") {
        r.findings.push(Finding::gap(
            "ENDPOINT-WSL-CONTEXT",
            "WSL result does not describe the Windows host",
        ));
    }
    if opts.commands && root.is_none() {
        if cfg!(windows) {
            let exe = env
                .get("SystemRoot")
                .map(|p| Path::new(p).join("System32/WindowsPowerShell/v1.0/powershell.exe"));
            let script = windows_script(opts.user_stores);
            match exe.and_then(|e| {
                probe(&e, &["-NoProfile", "-NonInteractive", "-Command", &script]).ok()
            }) {
                Some(b) => r
                    .findings
                    .extend(windows_records(&b, data, opts.user_stores)),
                None => r.findings.push(Finding::gap(
                    "ENDPOINT-WINDOWS-STORE",
                    "Windows store query unavailable",
                )),
            }
            let policy = r#"$ErrorActionPreference='Stop'; try { $p=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot' -ErrorAction SilentlyContinue; if($p.DisableRootAutoUpdate -eq 1){'DisableRootAutoUpdate=1'}else{'DisableRootAutoUpdate=0'}; if(Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate') { $a=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate'; if($a.DisallowedCertEncodedCtl){'DisallowedCtlPresent=True'}else{'DisallowedCtlPresent=False'} } else {'DisallowedCtlPresent=False'} } catch {'PolicyUnavailable'}"#;
            let policy_result = env
                .get("SystemRoot")
                .map(|p| Path::new(p).join("System32/WindowsPowerShell/v1.0/powershell.exe"))
                .and_then(|p| {
                    probe(&p, &["-NoProfile", "-NonInteractive", "-Command", policy]).ok()
                })
                .and_then(|b| safe::text(&b).ok());
            r.findings.extend(windows_policy_records(
                policy_result.as_deref().unwrap_or(""),
            ));
        }
        if cfg!(target_os = "macos") {
            let mut paths = vec![
                PathBuf::from("/System/Library/Keychains/SystemRootCertificates.keychain"),
                PathBuf::from("/Library/Keychains/System.keychain"),
            ];
            if opts.user_stores
                && let Some(h) = env.get("HOME")
            {
                paths.push(Path::new(h).join("Library/Keychains/login.keychain-db"));
            }
            for p in paths {
                match p.to_str().and_then(|p| {
                    probe(
                        Path::new("/usr/bin/security"),
                        &["find-certificate", "-a", "-p", p],
                    )
                    .ok()
                }) {
                    Some(b) => r.findings.extend(certs::findings(
                        &b,
                        data,
                        "macOS keychain",
                        false,
                        "ENDPOINT",
                    )),
                    None => r.findings.push(Finding::gap(
                        "ENDPOINT-MACOS-KEYCHAIN",
                        "Keychain enumeration unavailable",
                    )),
                }
            }
        }
        runtime_probes(data, &mut r);
        package_probe(root, data, &mut r);
    } else {
        r.findings.push(Finding::gap(
            "ENDPOINT-EXECUTABLE-PROBES-DISABLED",
            "OS stores and runtime/package probes requiring external executables were not run",
        ));
    }
    r.findings.push(Finding::gap("ENDPOINT-EFFECTIVE-TRUST-UNKNOWN","Browser revocation, Windows CTL freshness, running clients and effective chain acceptance are not established"));
    if let Some(target) = &opts.network {
        if !opts.commands || root.is_some() {
            r.findings.push(Finding::gap(
                "ENDPOINT-NETWORK-NOT-RUN",
                "Network probe requires explicit --commands and a real endpoint",
            ));
        } else {
            let (connect, sni) = host(target)?;
            match executable("openssl").and_then(|p| {
                probe(
                    &p,
                    &[
                        "s_client",
                        "-connect",
                        &connect,
                        "-servername",
                        &sni,
                        "-verify_return_error",
                        "-verify_hostname",
                        &sni,
                        "-showcerts",
                    ],
                )
                .ok()
            }) {
                Some(b) => {
                    r.findings.extend(certs::findings(
                        &b,
                        data,
                        "explicit network peer",
                        false,
                        "ENDPOINT",
                    ));
                    r.findings.push(Finding::gap("ENDPOINT-NETWORK-LIMIT","OpenSSL probe completed; other clients, proxies and future chains may differ"));
                }
                None => r.findings.push(Finding::gap(
                    "ENDPOINT-NETWORK-INCONCLUSIVE",
                    "TLS probe failed or was unavailable; rejection is not established",
                )),
            }
        }
    }
    r.findings.push(Finding::new("ENDPOINT-CREDENTIAL-REVIEW","Credential review depends on evidence of actual exposure","unable_to_assess","review_required").evidence("guidance","Review connections and authentication during the exposure window. Rotate affected credentials if evidence warrants it; do not infer blanket rotation or no rotation from this scan."));
    r.notes.push("Executable probes are opt-in and trust installed tools, PATH and startup hooks; they may write or communicate. Network mounts can cause OS-level traffic. No endpoint audit proves that interception never happened.".into());
    r.finish();
    Ok(r)
}
fn runtime_probes(data: &Data, r: &mut Report) {
    let version_regex = Regex::new(r"[0-9]+(?:\.[0-9]+){1,3}\b").expect("static regex");
    for (exe, args, name) in [
        ("node", vec!["--version"], "node"),
        ("go", vec!["version"], "go"),
        ("uv", vec!["--version"], "uv"),
        ("pip", vec!["--version"], "pip"),
        ("claude", vec!["--version"], "@anthropic-ai/claude-code"),
    ] {
        if let Some(path) = executable(exe) {
            let text = probe(&path, &args)
                .ok()
                .and_then(|b| String::from_utf8(b).ok());
            let version = text
                .as_ref()
                .and_then(|t| version_regex.find(t).map(|m| m.as_str().to_owned()));
            if let Some(v) = version {
                for p in safe::array(&data.policy, "packages") {
                    if safe::string(p, "name") == name {
                        r.findings.push(versions::finding(
                            name,
                            &v,
                            true,
                            p,
                            "ENDPOINT",
                            "installed executable",
                        ));
                    }
                }
            } else {
                r.findings.push(
                    Finding::gap(
                        "ENDPOINT-RUNTIME-UNKNOWN",
                        "Installed executable version unavailable",
                    )
                    .evidence("component", name),
                );
            }
        }
    }
    if let Some(node) = executable("node") {
        match probe(
            &node,
            &[
                "-e",
                r"process.stdout.write(require('tls').rootCertificates.join('\n'))",
            ],
        ) {
            Ok(b) => r.findings.extend(certs::findings(
                &b,
                data,
                "Node built-in roots",
                false,
                "ENDPOINT",
            )),
            Err(_) => r.findings.push(Finding::gap(
                "ENDPOINT-NODE-ROOTS",
                "Node roots unavailable",
            )),
        }
    }
    for name in ["curl", "openssl", "java", "deno", "codex"] {
        if executable(name).is_some() {
            r.findings.push(
                Finding::gap(
                    "ENDPOINT-RUNTIME-WATCHLIST",
                    "Installed client has independent trust behavior requiring vendor review",
                )
                .evidence("component", name),
            );
        }
    }
    r.findings.push(Finding::gap("ENDPOINT-PYTHON-ENVIRONMENTS","Installed Python/certifi environments are not executed; audit their lockfiles and explicit CA bundles separately"));
}
fn package_probe(root: Option<&Path>, data: &Data, r: &mut Report) {
    let os = safe::read(&mapped(root, Path::new("/etc/os-release")), 65536, true)
        .ok()
        .and_then(|b| safe::text(&b).ok())
        .unwrap_or_default();
    let pairs: BTreeMap<_, _> = os
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k, v.trim_matches(['\'', '"'])))
        .collect();
    let id = if cfg!(target_os = "macos") {
        "darwin"
    } else {
        pairs.get("ID").copied().unwrap_or("")
    };
    let version = pairs.get("VERSION_ID").copied().unwrap_or("");
    let mut matched = false;
    for p in safe::array(&data.policy, "os_ca_bundles") {
        let prefix = safe::string(p, "os_version_prefix");
        if !safe::list(p, "os_ids").iter().any(|s| s == id)
            || (!prefix.is_empty()
                && version != prefix
                && !version.starts_with(&format!("{prefix}.")))
        {
            continue;
        }
        matched = true;
        let package = safe::string(p, "package");
        if !package
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            continue;
        }
        let (exe, args) = match safe::string(p, "package_manager") {
            "dpkg" => ("dpkg-query", vec!["-W", "-f=${Version}", package]),
            "rpm" => ("rpm", vec!["-q", "--qf", "%{VERSION}", package]),
            "pacman" => ("pacman", vec!["-Q", package]),
            "apk" => ("apk", vec!["info", "-v", package]),
            "brew" => ("brew", vec!["list", "--versions", package]),
            _ => continue,
        };
        let value = executable(exe)
            .and_then(|e| probe(&e, &args).ok())
            .and_then(|b| String::from_utf8(b).ok());
        if let Some(v) = value {
            let v = v.trim();
            let v = if exe == "pacman" || exe == "brew" {
                v.split_whitespace().nth(1).unwrap_or("")
            } else if exe == "apk" {
                v.strip_prefix(&format!("{package}-")).unwrap_or("")
            } else {
                v
            };
            r.findings.push(versions::finding(
                package,
                v,
                true,
                p,
                "ENDPOINT",
                "OS package query",
            ));
        } else {
            r.findings.push(Finding::gap(
                "ENDPOINT-CA-PACKAGE-UNKNOWN",
                "OS CA package version unavailable",
            ));
        }
    }
    if !matched {
        r.findings.push(Finding::gap(
            "ENDPOINT-CA-PACKAGE-NO-POLICY",
            "No exact distributor policy matches this endpoint",
        ));
    }
}
