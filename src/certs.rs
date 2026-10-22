use crate::{data::Data, model::Finding, safe};
use base64::{Engine, engine::general_purpose::STANDARD};

fn tlv(b: &[u8], start: usize) -> Result<(u8, usize, usize), String> {
    let tag = *b.get(start).ok_or("truncated DER")?;
    let n = *b.get(start + 1).ok_or("truncated DER length")?;
    let mut pos = start + 2;
    let len = if n < 128 {
        n as usize
    } else {
        let count = (n & 127) as usize;
        if count == 0 || count > 4 {
            return Err("unsupported DER length".into());
        }
        let mut len = 0usize;
        for _ in 0..count {
            len = (len << 8) | (*b.get(pos).ok_or("truncated DER length")? as usize);
            pos += 1;
        }
        len
    };
    let end = pos.checked_add(len).ok_or("DER overflow")?;
    if end > b.len() {
        return Err("DER exceeds input".into());
    }
    Ok((tag, pos, end))
}
pub fn spki(der: &[u8]) -> Result<String, String> {
    let (tag, start, end) = tlv(der, 0)?;
    if tag != 0x30 || end != der.len() {
        return Err("not a complete DER certificate".into());
    }
    let (tag, mut pos, tbs_end) = tlv(&der[..end], start)?;
    if tag != 0x30 {
        return Err("invalid certificate body".into());
    }
    let mut fields = vec![];
    while pos < tbs_end {
        let f = tlv(&der[..tbs_end], pos)?;
        fields.push((pos, f));
        pos = f.2;
    }
    let offset = usize::from(fields.first().is_some_and(|f| f.1.0 == 0xa0));
    if fields.len() < offset + 6 || fields[offset].1.0 != 2 {
        return Err("invalid certificate fields".into());
    }
    let (raw, (tag, body, end)) = fields[offset + 5];
    if tag != 0x30 {
        return Err("invalid SPKI".into());
    }
    let a = tlv(&der[..end], body)?;
    let key = tlv(&der[..end], a.2)?;
    if a.0 != 0x30 || key.0 != 3 || key.2 != end {
        return Err("invalid SPKI shape".into());
    }
    Ok(safe::digest(&der[raw..end]))
}
#[derive(Default)]
pub struct Bundle {
    pub hashes: Vec<String>,
    pub invalid: usize,
}
pub fn parse(blob: &[u8]) -> Bundle {
    let mut out = Bundle::default();
    if blob.starts_with(&[0xfe, 0xed, 0xfe, 0xed]) || blob.starts_with(&[0xce, 0xce, 0xce, 0xce]) {
        match jks(blob) {
            Ok(certs) => {
                for der in certs {
                    match spki(der) {
                        Ok(h) => out.hashes.push(h),
                        Err(_) => out.invalid += 1,
                    }
                }
            }
            Err(_) => out.invalid += 1,
        }
        return out;
    }
    let text = String::from_utf8_lossy(blob);
    let begin = "-----BEGIN CERTIFICATE-----";
    let end = "-----END CERTIFICATE-----";
    if text.contains(begin) {
        for part in text.split(begin).skip(1) {
            let Some((body, _)) = part.split_once(end) else {
                out.invalid += 1;
                continue;
            };
            let encoded: Vec<u8> = body.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
            match STANDARD
                .decode(encoded)
                .ok()
                .and_then(|der| spki(&der).ok())
            {
                Some(h) => out.hashes.push(h),
                None => out.invalid += 1,
            }
        }
    } else {
        match spki(blob) {
            Ok(h) => out.hashes.push(h),
            Err(_) => out.invalid += 1,
        }
    }
    out
}
pub fn findings(blob: &[u8], data: &Data, label: &str, blocked: bool, scope: &str) -> Vec<Finding> {
    let bundle = parse(blob);
    let mut found = vec![];
    for h in &bundle.hashes {
        if safe::array(&data.incident, "compromised_intermediates")
            .iter()
            .any(|v| safe::string(v, "spki_sha256").eq_ignore_ascii_case(h))
        {
            let mut f = Finding::new(
                &format!(
                    "{scope}-SPKI-{}",
                    if blocked {
                        "BLOCKLIST-ENTRY"
                    } else {
                        "PRESENT"
                    }
                ),
                if blocked {
                    "Compromised key appears in a blocklist; client rejection is not established"
                } else {
                    "Compromised intermediate key present; client acceptance is not established"
                },
                "known_indicator",
                if blocked {
                    "review_required"
                } else {
                    "action_required"
                },
            )
            .evidence("SPKI SHA-256", h)
            .at(label);
            f.tags.push("compromised-spki-present".into());
            f.references = safe::array(&data.incident, "sources")
                .iter()
                .map(|v| safe::string(v, "url").to_owned())
                .collect();
            f.remediation=vec!["Update the CA bundle/client through its official channel; rebuild dependent images and restart processes. Do not indiscriminately delete related roots.".into()];
            found.push(f);
        }
    }
    if found.is_empty() && !bundle.hashes.is_empty() {
        found.push(
            Finding::new(
                &format!("{scope}-SPKI-NOT-FOUND"),
                "No compromised SPKI matched in parsed certificates",
                "not_found",
                "none",
            )
            .evidence("certificates parsed", &bundle.hashes.len().to_string())
            .at(label),
        );
    }
    if bundle.invalid > 0 || bundle.hashes.is_empty() {
        found.push(
            Finding::gap(
                &format!("{scope}-BUNDLE-INCOMPLETE"),
                "Certificate source is incomplete, empty or unsupported",
            )
            .at(label),
        );
    }
    found
}
struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.p.checked_add(n).ok_or("keystore overflow")?;
        let b = self.b.get(self.p..end).ok_or("truncated keystore")?;
        self.p = end;
        Ok(b)
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| "invalid integer")?,
        ))
    }
    fn utf(&mut self) -> Result<(), String> {
        let n =
            u16::from_be_bytes(self.take(2)?.try_into().map_err(|_| "invalid integer")?) as usize;
        self.take(n)?;
        Ok(())
    }
    fn cert(&mut self, v: u32) -> Result<&'a [u8], String> {
        if v == 2 {
            self.utf()?;
        }
        let n = self.u32()? as usize;
        self.take(n)
    }
}
fn jks(b: &[u8]) -> Result<Vec<&[u8]>, String> {
    let mut r = Reader { b, p: 4 };
    let version = r.u32()?;
    if version != 1 && version != 2 {
        return Err("unsupported keystore version".into());
    }
    let n = r.u32()?;
    if n > 20000 {
        return Err("keystore limit".into());
    }
    let mut out = vec![];
    for _ in 0..n {
        let tag = r.u32()?;
        r.utf()?;
        r.take(8)?;
        match tag {
            2 => out.push(r.cert(version)?),
            1 => {
                let key_len = r.u32()? as usize;
                r.take(key_len)?;
                let chain_len = r.u32()?;
                if chain_len > 20000 {
                    return Err("keystore chain limit".into());
                }
                for _ in 0..chain_len {
                    r.cert(version)?;
                }
            }
            _ => return Err("unsupported keystore entry".into()),
        }
    }
    Ok(out)
}
