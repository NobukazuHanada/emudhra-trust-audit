use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    path::{Component, Path},
};

pub fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn normalize(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\r' {
            out.push(b'\n');
            if bytes.get(i + 1) == Some(&b'\n') {
                i += 1;
            }
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    out
}
pub fn is_link(meta: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        meta.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        meta.file_type().is_symlink()
    }
}
pub fn no_links(path: &Path) -> Result<(), String> {
    let mut p = std::path::PathBuf::new();
    for c in path.components() {
        p.push(c);
        // A Windows drive/UNC prefix alone is not a filesystem root (in
        // particular canonicalize returns verbatim paths such as \\?\C:\).
        // Check it after RootDir has been appended, then every descendant.
        if matches!(c, Component::Prefix(_)) {
            continue;
        }
        let m = fs::symlink_metadata(&p).map_err(|_| "path unavailable")?;
        if is_link(&m) {
            return Err("linked or reparse path excluded".into());
        }
    }
    Ok(())
}
pub fn read(path: &Path, limit: usize, follow: bool) -> Result<Vec<u8>, String> {
    if !follow {
        no_links(path)?;
    }
    let m = fs::metadata(path).map_err(|_| "file unavailable or permission denied")?;
    if !m.is_file() || m.len() > limit as u64 {
        return Err("not a regular file or exceeds size limit".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | if follow { 0 } else { libc::O_NOFOLLOW });
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        if !follow {
            options.custom_flags(0x00200000);
        }
    }
    let file = options
        .open(path)
        .map_err(|_| "file unavailable or permission denied")?;
    let m = file.metadata().map_err(|_| "file metadata unavailable")?;
    if !m.is_file() || (!follow && is_link(&m)) || m.len() > limit as u64 {
        return Err("unsafe file or size limit".into());
    }
    let mut b = vec![];
    file.take(limit as u64 + 1)
        .read_to_end(&mut b)
        .map_err(|_| "file read failed")?;
    if b.len() > limit {
        return Err("file exceeds size limit".into());
    }
    Ok(b)
}
pub fn project_read(root: &Path, relative: &Path, limit: usize) -> Result<Vec<u8>, String> {
    if relative.is_absolute()
        || relative
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err("invalid relative path".into());
    }
    let p = root.join(relative);
    no_links(&p)?;
    if !p
        .canonicalize()
        .map_err(|_| "path unavailable")?
        .starts_with(root)
    {
        return Err("outside project".into());
    }
    read(&p, limit, false)
}
// Never expose arbitrary input filenames, certificate subjects, command output or environment values.
// Opaque stable references let a user correlate repeated findings without disclosing path secrets.
pub fn location(relative: &Path) -> String {
    let portable = relative
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    format!("file:{}", &digest(portable.as_bytes())[..16])
}
pub fn text(bytes: &[u8]) -> Result<String, String> {
    String::from_utf8(normalize(bytes)).map_err(|_| "invalid UTF-8; not examined".into())
}
pub fn string<'a>(v: &'a serde_json::Value, k: &str) -> &'a str {
    v.get(k).and_then(|v| v.as_str()).unwrap_or("")
}
pub fn list(v: &serde_json::Value, k: &str) -> Vec<String> {
    v.get(k)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}
pub fn array<'a>(v: &'a serde_json::Value, k: &str) -> &'a [serde_json::Value] {
    v.get(k)
        .and_then(|v| v.as_array())
        .map(Vec::as_slice)
        .unwrap_or(&[])
}
