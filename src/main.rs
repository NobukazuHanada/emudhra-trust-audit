use emudhra_trust_audit::{certs, data::Data, endpoint, model::Report, project, safe};
use std::{
    env,
    fs::OpenOptions,
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
};
const HELP: &str = "emudhra-trust-audit — unofficial, read-only CA trust audit\n\nUsage:\n  emudhra-trust-audit endpoint [--bundle PATH] [--commands] [--no-user-stores]\n  emudhra-trust-audit project [PATH] [--scan-bundle PATH] [--no-containers]\n  emudhra-trust-audit data [--verify] [--checksums DIR]\n  emudhra-trust-audit explain FINDING_ID\n  emudhra-trust-audit file-id RELATIVE_PATH\n\nCommon: --format json|text|sarif, --data-dir DIR, --output NEW_FILE\nEndpoint: --no-commands (default, overrides --commands), --fs-root DIR\n          --network-test HOST (explicit network consent; also requires --commands)\nExit: 0 no action found, 1 review, 2 action, 3 audit error.\nNo Python or Rust runtime is required. No automatic remediation.\n";
fn execute(args: Vec<String>) -> Result<(String, u8, Option<PathBuf>), String> {
    if args.is_empty() || args == ["--help"] || args == ["-h"] {
        return Ok((HELP.into(), 0, None));
    }
    if args == ["--version"] {
        return Ok((
            format!("emudhra-trust-audit {}", env!("CARGO_PKG_VERSION")),
            0,
            None,
        ));
    }
    let command = &args[0];
    let mut format = "json".to_owned();
    let mut output = None;
    let mut data_dir = None;
    let mut path = PathBuf::from(".");
    let mut positional = false;
    let mut bundle = None;
    let mut containers = true;
    let mut checksums = None;
    let mut options = endpoint::Options {
        commands: false,
        user_stores: true,
        root: None,
        bundles: vec![],
        network: None,
    };
    let mut no_commands = false;
    let mut detail = String::new();
    let mut i = 1;
    while i < args.len() {
        let key = &args[i];
        i += 1;
        match key.as_str() {
            "--commands" if command == "endpoint" => options.commands = true,
            "--no-commands" if command == "endpoint" => no_commands = true,
            "--no-user-stores" if command == "endpoint" => options.user_stores = false,
            "--no-containers" if command == "project" => containers = false,
            "--verify" if command == "data" => {}
            "--format" | "--output" | "--data-dir" | "--bundle" | "--scan-bundle" | "--fs-root"
            | "--network-test" | "--checksums" => {
                let value = args.get(i).ok_or("missing option argument")?;
                i += 1;
                match key.as_str() {
                    "--format" => format = value.clone(),
                    "--output" => output = Some(PathBuf::from(value)),
                    "--data-dir" => data_dir = Some(PathBuf::from(value)),
                    "--bundle" if command == "endpoint" => {
                        options.bundles.push(PathBuf::from(value))
                    }
                    "--scan-bundle" if command == "project" => bundle = Some(PathBuf::from(value)),
                    "--fs-root" if command == "endpoint" => {
                        options.root = Some(PathBuf::from(value))
                    }
                    "--network-test" if command == "endpoint" => {
                        options.network = Some(value.clone())
                    }
                    "--checksums" if command == "data" => checksums = Some(PathBuf::from(value)),
                    _ => return Err("option does not apply to this command".into()),
                }
            }
            value if !value.starts_with('-') && !positional => {
                positional = true;
                path = PathBuf::from(value);
                detail = value.to_owned();
            }
            _ => return Err("unknown option or extra argument".into()),
        }
    }
    if !["json", "text", "sarif"].contains(&format.as_str()) {
        return Err("unsupported output format".into());
    }
    if no_commands {
        options.commands = false;
    }
    if command == "file-id" {
        if !positional
            || path.is_absolute()
            || path
                .components()
                .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return Err("file-id requires a relative path without traversal".into());
        }
        return Ok((safe::location(&path), 0, output));
    }
    if let Some(dir) = checksums {
        return Ok((
            serde_json::to_string_pretty(&Data::checksums(&dir)?)
                .map_err(|_| "cannot serialize checksums")?,
            0,
            output,
        ));
    }
    let data = Data::load(data_dir.as_deref())?;
    if command == "data" {
        let v = serde_json::json!({"checksum_status":"verified","compromised_spki_count":safe::array(&data.incident,"compromised_intermediates").len(),"data_sources":data.sources()});
        return Ok((
            serde_json::to_string_pretty(&v).map_err(|_| "cannot serialize data")?,
            0,
            output,
        ));
    }
    if command == "explain" {
        if !positional || !detail.bytes().all(|b| b.is_ascii_uppercase() || b == b'-') {
            return Err("finding identifier required".into());
        }
        let rule = detail
            .strip_prefix("PROJECT-")
            .or_else(|| detail.strip_prefix("ENDPOINT-"))
            .and_then(|id| {
                safe::array(&data.rules, "rules")
                    .iter()
                    .find(|r| safe::string(r, "id") == id)
            });
        let explanation = if let Some(rule) = rule {
            serde_json::json!({"title":rule["title"],"method":rule["description"],"remediation":rule["remediation"],"references":rule["references"]})
        } else {
            serde_json::json!({"method":"Offline evidence collection, exact SPKI comparison, recorded version policy or a disclosed coverage gap.","limits":"Presence and versions do not establish effective chain acceptance. unable_to_assess is never a pass.","remediation":"Read the finding's evidence and remediation; confirm current vendor advisories. Never disable TLS or indiscriminately remove roots."})
        };
        return Ok((
            serde_json::to_string_pretty(&explanation).map_err(|_| "serialization failed")?,
            0,
            output,
        ));
    }
    if positional && command != "project" {
        return Err("unexpected positional argument".into());
    }
    let mut report = match command.as_str() {
        "endpoint" => endpoint::audit(&options, &data)?,
        "project" => project::audit(&path, &data, containers)?,
        _ => return Err("unknown command".into()),
    };
    if let Some(p) = bundle {
        match safe::read(&p, 16_777_216, false) {
            Ok(b) => report.findings.extend(certs::findings(
                &b,
                &data,
                "explicit bundle",
                false,
                "PROJECT",
            )),
            Err(_) => report
                .findings
                .push(emudhra_trust_audit::model::Finding::gap(
                    "PROJECT-BUNDLE-UNREADABLE",
                    "Explicit bundle unavailable, linked or oversized",
                )),
        }
        report.finish();
    }
    let code = report.exit_code;
    let text = match format.as_str() {
        "text" => {
            let mut t = format!(
                "emudhra-trust-audit {}: {} (exit {})\n",
                report.tool_version, report.verdict, code
            );
            for f in &report.findings {
                t.push_str(&format!(
                    "{} [{}; {}] {}\n",
                    f.id, f.status, f.confidence, f.title
                ));
                for e in &f.evidence {
                    t.push_str(&format!("  {}\n", e));
                }
                for r in &f.remediation {
                    t.push_str(&format!("  Remedy: {r}\n"));
                }
            }
            t
        }
        "sarif" => {
            serde_json::to_string_pretty(&report.sarif()).map_err(|_| "serialization failed")?
        }
        _ => serde_json::to_string_pretty(&report).map_err(|_| "serialization failed")?,
    };
    Ok((text, code, output))
}
fn main() -> ExitCode {
    let args: Result<Vec<String>, _> = env::args_os().skip(1).map(|s| s.into_string()).collect();
    let result = args
        .map_err(|_| "arguments must be Unicode".to_owned())
        .and_then(execute);
    let (text, code, output) = match result {
        Ok(v) => v,
        Err(error) => {
            let mut r = Report::new("audit");
            r.errors.push(error);
            r.finish();
            (
                serde_json::to_string_pretty(&r).unwrap_or_else(|_| "{\"exit_code\":3}".into()),
                3,
                None,
            )
        }
    };
    let write = if let Some(path) = output {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .and_then(|mut f| writeln!(f, "{text}"))
    } else {
        writeln!(io::stdout().lock(), "{text}")
    };
    if write.is_err() {
        let _ = writeln!(
            io::stderr(),
            "Output unavailable; existing files are never overwritten."
        );
        return ExitCode::from(3);
    }
    ExitCode::from(code)
}
