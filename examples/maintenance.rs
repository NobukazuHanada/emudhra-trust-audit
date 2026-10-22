//! Maintainer-only checks and third-party attribution packaging. Not shipped as a product executable.
use serde_json::Value;
use std::{env, fs, path::Path, process::Command};
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("licenses") {
        let dest = Path::new(args.get(1).ok_or("destination required")?);
        fs::create_dir(dest)?;
        let output = Command::new(env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
            .args(["metadata", "--locked", "--offline", "--format-version", "1"])
            .output()?;
        if !output.status.success() {
            return Err("cargo metadata failed".into());
        }
        let v: Value = serde_json::from_slice(&output.stdout)?;
        let mut summary = String::from(
            "# Dependency licenses\n\nGenerated from Cargo.lock; includes build dependencies and all resolved platforms.\n\n",
        );
        for p in v["packages"].as_array().ok_or("packages missing")? {
            if p["source"].is_null() {
                continue;
            }
            let n = p["name"].as_str().ok_or("name missing")?;
            let version = p["version"].as_str().ok_or("version missing")?;
            let license = p["license"].as_str().ok_or("license metadata missing")?;
            // Do not silently accept unknown/copyleft licenses in the maintainer packaging step.
            let allowed = [
                "MIT",
                "Apache-2.0",
                "BSD-2-Clause",
                "BSD-3-Clause",
                "ISC",
                "Unicode-3.0",
                "Unlicense",
                "Zlib",
            ];
            if license
                .split([' ', '(', ')', '/'])
                .filter(|s| !s.is_empty() && *s != "OR" && *s != "AND")
                .any(|s| !allowed.contains(&s))
            {
                return Err(format!("license requires review: {n}: {license}").into());
            }
            summary.push_str(&format!("- {n} {version}: {license}\n"));
            let root = Path::new(p["manifest_path"].as_str().ok_or("manifest missing")?)
                .parent()
                .ok_or("manifest directory missing")?;
            let target = dest.join(format!("{n}-{version}"));
            fs::create_dir(&target)?;
            let mut copied = 0;
            for entry in fs::read_dir(root)? {
                let entry = entry?;
                let name = entry.file_name();
                let upper = name.to_string_lossy().to_uppercase();
                if entry.file_type()?.is_file()
                    && (upper.starts_with("LICENSE")
                        || upper.starts_with("COPYING")
                        || upper.starts_with("NOTICE"))
                {
                    fs::copy(entry.path(), target.join(name))?;
                    copied += 1;
                }
            }
            if copied == 0 {
                return Err(format!("license text missing: {n}").into());
            }
        }
        let sysroot = Command::new("rustc")
            .args(["--print", "sysroot"])
            .output()?;
        if !sysroot.status.success() {
            return Err("rustc sysroot unavailable".into());
        }
        let sysroot_text = String::from_utf8(sysroot.stdout)?;
        let rust_docs = Path::new(sysroot_text.trim()).join("share/doc/rust");
        let runtime = dest.join("rust-standard-library");
        fs::create_dir(&runtime)?;
        fs::copy(
            rust_docs.join("COPYRIGHT-library.html"),
            runtime.join("COPYRIGHT-library.html"),
        )?;
        fs::create_dir(runtime.join("licenses"))?;
        for entry in fs::read_dir(rust_docs.join("licenses"))? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                fs::copy(
                    entry.path(),
                    runtime.join("licenses").join(entry.file_name()),
                )?;
            }
        }
        summary.push_str("\nRust standard-library notices and the toolchain license catalog are also included. The catalog may list components not linked into this executable.\n");
        fs::write(dest.join("INDEX.md"), summary)?;
        println!("Dependency license metadata and texts verified");
    } else if args.first().map(String::as_str) == Some("skills") {
        for name in ["endpoint-trust-audit", "project-trust-audit"] {
            let text = fs::read_to_string(format!("skills/{name}/SKILL.md"))?;
            let front = text
                .strip_prefix("---\n")
                .and_then(|s| s.split_once("\n---\n"))
                .ok_or("invalid skill frontmatter")?
                .0;
            if !front.lines().any(|l| l == format!("name: {name}"))
                || !front
                    .lines()
                    .any(|l| l.starts_with("description: ") && l.len() > 14)
            {
                return Err("missing skill name/description".into());
            }
            for wrapper in ["run.sh", "run.ps1"] {
                if !Path::new(&format!("skills/{name}/{wrapper}")).is_file() {
                    return Err("missing wrapper".into());
                }
            }
        }
        println!("Both skill frontmatters and wrapper paths verified");
    } else {
        return Err("usage: maintenance licenses NEW_DIR | skills".into());
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
