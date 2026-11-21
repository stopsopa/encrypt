//! Header parsing and serialising (SPEC.md section 2).

use crate::util::{b64url_decode, b64url_encode, latin1, Error};

/// Argon2id cost parameters; `m` is in KiB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    pub const DEFAULT: KdfParams = KdfParams { m: 65536, t: 3, p: 4 };
    pub const STRONG: KdfParams = KdfParams {
        m: 1_048_576,
        t: 4,
        p: 4,
    };

    pub(crate) fn in_range(&self) -> bool {
        (1..=16).contains(&self.p) && (1..=64).contains(&self.t) && self.m >= 8 * self.p && self.m <= 4_194_304
    }
}

/// Argon2id cost for new password slots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kdf {
    /// `default`, `strong` or `m=<M>,t=<T>,p=<P>`.
    Profile(String),
    Params(KdfParams),
}

impl From<&str> for Kdf {
    fn from(s: &str) -> Self {
        Kdf::Profile(s.to_string())
    }
}

impl From<KdfParams> for Kdf {
    fn from(p: KdfParams) -> Self {
        Kdf::Params(p)
    }
}

/// `[1-9][0-9]{0,max_extra}` as a number.
fn positive(s: &[u8], max_extra: usize) -> Option<u32> {
    if s.is_empty() || s.len() > 1 + max_extra || s[0] == b'0' || !s.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(s).ok()?.parse().ok()
}

/// `m=<M>,t=<T>,p=<P>` with the digit counts the reference accepts.
fn parse_kdf_triplet(s: &[u8]) -> Option<KdfParams> {
    let mut it = s.split(|&c| c == b',');
    let m = positive(it.next()?.strip_prefix(b"m=")?, 7)?;
    let t = positive(it.next()?.strip_prefix(b"t=")?, 1)?;
    let p = positive(it.next()?.strip_prefix(b"p=")?, 1)?;
    if it.next().is_some() {
        return None;
    }
    Some(KdfParams { m, t, p })
}

pub(crate) fn parse_kdf(kdf: Option<&Kdf>) -> Result<KdfParams, Error> {
    let k = match kdf {
        None => KdfParams::DEFAULT,
        Some(Kdf::Params(p)) => *p,
        Some(Kdf::Profile(s)) => match s.as_str() {
            "default" => KdfParams::DEFAULT,
            "strong" => KdfParams::STRONG,
            other => parse_kdf_triplet(other.as_bytes()).ok_or_else(|| {
                Error::usage(format!(
                    "invalid kdf profile '{other}' (use default, strong or m=..,t=..,p=..)"
                ))
            })?,
        },
    };
    if !k.in_range() {
        return Err(Error::usage(
            "kdf parameters out of range (8*p <= m <= 4194304, 1 <= t <= 64, 1 <= p <= 16)",
        ));
    }
    Ok(k)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Lines,
    Blob,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Lines => "lines",
            Mode::Blob => "blob",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Slot {
    Pw {
        kdf: KdfParams,
        salt: Vec<u8>,
        wrapped: Vec<u8>,
    },
    Ssh {
        key_type: String,
        fingerprint: String,
        salt: Vec<u8>,
        wrapped: Vec<u8>,
    },
}

pub(crate) struct ParsedFile<'a> {
    pub mode: Mode,
    pub ws: bool,
    pub pad: usize,
    pub chunk: usize,
    pub header_line: String,
    pub slots: Vec<Slot>,
    pub slot_lines: Vec<String>,
    pub seal: Option<Vec<u8>>,
    pub body: &'a [u8],
}

pub(crate) fn header_line_for(mode: Mode, ws: bool, pad: usize, chunk: usize) -> String {
    match mode {
        Mode::Lines => format!("#ssenc1 lines ws={} pad={}", ws as u8, pad),
        Mode::Blob => format!("#ssenc1 blob chunk={chunk}"),
    }
}

pub(crate) fn pw_slot_line(kdf: KdfParams, salt: &[u8], wrapped: &[u8]) -> String {
    format!(
        "#slot pw argon2id m={},t={},p={} {} {}",
        kdf.m,
        kdf.t,
        kdf.p,
        b64url_encode(salt),
        b64url_encode(wrapped)
    )
}

pub(crate) fn ssh_slot_line(key_type: &str, fingerprint: &str, salt: &[u8], wrapped: &[u8]) -> String {
    format!(
        "#slot ssh {} {} {} {}",
        key_type,
        fingerprint,
        b64url_encode(salt),
        b64url_encode(wrapped)
    )
}

fn decode_field(s: &[u8], len: usize, what: &str) -> Result<Vec<u8>, Error> {
    match b64url_decode(s) {
        Some(b) if b.len() == len => Ok(b),
        _ => Err(Error::malformed(format!("invalid {what} in header"))),
    }
}

fn is_b64url_field(s: &[u8]) -> bool {
    !s.is_empty() && s.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

/// Splits at single spaces into exactly `N` fields.
fn fields<const N: usize>(s: &[u8]) -> Option<[&[u8]; N]> {
    let mut out = [&s[..0]; N];
    let mut it = s.split(|&c| c == b' ');
    for slot in out.iter_mut() {
        *slot = it.next()?;
    }
    if it.next().is_some() {
        return None;
    }
    Some(out)
}

fn match_pw_slot(line: &[u8]) -> Option<(KdfParams, &[u8], &[u8])> {
    let [params, salt, wrapped] = fields::<3>(line.strip_prefix(b"#slot pw argon2id ")?)?;
    let kdf = parse_kdf_triplet(params)?;
    (is_b64url_field(salt) && is_b64url_field(wrapped)).then_some((kdf, salt, wrapped))
}

fn match_ssh_slot(line: &[u8]) -> Option<[&[u8]; 4]> {
    let [key_type, fp, salt, wrapped] = fields::<4>(line.strip_prefix(b"#slot ssh ")?)?;
    if key_type != b"ssh-ed25519" && key_type != b"ssh-rsa" {
        return None;
    }
    let hash = fp.strip_prefix(b"SHA256:")?;
    if hash.len() != 43
        || !hash
            .iter()
            .all(|&c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
    {
        return None;
    }
    (is_b64url_field(salt) && is_b64url_field(wrapped)).then_some([key_type, fp, salt, wrapped])
}

fn parse_slot_line(line: &[u8]) -> Result<Slot, Error> {
    if let Some((kdf, salt, wrapped)) = match_pw_slot(line) {
        let salt = decode_field(salt, 16, "password slot salt")?;
        let wrapped = decode_field(wrapped, 48, "wrapped key")?;
        if !kdf.in_range() {
            return Err(Error::malformed("argon2id parameters out of range in header"));
        }
        return Ok(Slot::Pw { kdf, salt, wrapped });
    }
    if let Some([key_type, fp, salt, wrapped]) = match_ssh_slot(line) {
        return Ok(Slot::Ssh {
            key_type: latin1(key_type),
            fingerprint: latin1(fp),
            salt: decode_field(salt, 32, "ssh slot salt")?,
            wrapped: decode_field(wrapped, 48, "wrapped key")?,
        });
    }
    Err(Error::malformed("unrecognised slot line in header"))
}

/// The line starting at `pos` without its LF and one optional CR, and the offset after it.
/// Lines over 1024 bytes are cut to 16 bytes: they can only be body lines or invalid.
fn peek_line(input: &[u8], pos: usize) -> Option<(&[u8], usize)> {
    if pos >= input.len() {
        return None;
    }
    let (mut end, next) = match input[pos..].iter().position(|&c| c == b'\n') {
        Some(i) => (pos + i, pos + i + 1),
        None => (input.len(), input.len()),
    };
    if end > pos && input[end - 1] == b'\r' {
        end -= 1;
    }
    if end - pos > 1024 {
        return Some((&input[pos..pos + 16], next));
    }
    Some((&input[pos..end], next))
}

fn parse_header_line(line: &[u8]) -> Result<(Mode, bool, usize, usize), Error> {
    if let Some(rest) = line.strip_prefix(b"#ssenc1 lines ws=") {
        if let Some([ws, pad]) = fields::<2>(rest) {
            if let (true, Some(pad)) = (ws == b"0" || ws == b"1", pad.strip_prefix(b"pad=")) {
                let n = if pad == b"0" { Some(0) } else { positive(pad, 3) };
                if let Some(n) = n {
                    if n > 4096 {
                        return Err(Error::malformed("pad out of range in header"));
                    }
                    return Ok((Mode::Lines, ws == b"1", n as usize, 0));
                }
            }
        }
    }
    if let Some(n) = line.strip_prefix(b"#ssenc1 blob chunk=").and_then(|c| positive(c, 6)) {
        if n > 1_048_576 {
            return Err(Error::malformed("chunk out of range in header"));
        }
        return Ok((Mode::Blob, true, 0, n as usize));
    }
    Err(Error::malformed("invalid '#ssenc1' header line"))
}

pub(crate) fn parse_file(input: &[u8]) -> Result<ParsedFile<'_>, Error> {
    let (first, mut pos) = match peek_line(input, 0) {
        Some((text, next)) if text.starts_with(b"#ssenc1 ") => (text, next),
        _ => return Err(Error::malformed("not an ssenc1 file (missing '#ssenc1' header)")),
    };
    let (mode, ws, pad, chunk) = parse_header_line(first)?;
    let mut out = ParsedFile {
        mode,
        ws,
        pad,
        chunk,
        header_line: latin1(first),
        slots: Vec::new(),
        slot_lines: Vec::new(),
        seal: None,
        body: &input[..0],
    };
    while let Some((line, next)) = peek_line(input, pos) {
        if line.starts_with(b"#slot ") {
            if out.seal.is_some() {
                return Err(Error::malformed("slot line after seal line"));
            }
            out.slots.push(parse_slot_line(line)?);
            out.slot_lines.push(latin1(line));
        } else if line.starts_with(b"#seal ") {
            if out.seal.is_some() || out.mode != Mode::Lines {
                return Err(Error::malformed("unexpected seal line"));
            }
            if !is_b64url_field(&line[6..]) {
                return Err(Error::malformed("invalid seal line"));
            }
            out.seal = Some(decode_field(&line[6..], 32, "seal")?);
        } else {
            break;
        }
        pos = next;
    }
    if out.slots.is_empty() {
        return Err(Error::malformed("header has no key slots"));
    }
    out.body = &input[pos..];
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::ErrorKind;

    const SALT: &str = "AAAAAAAAAAAAAAAAAAAAAA";
    const WRAPPED: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn pw_slot() -> String {
        format!("#slot pw argon2id m=8192,t=1,p=1 {SALT} {WRAPPED}")
    }

    fn kind(input: &str) -> ErrorKind {
        parse_file(input.as_bytes()).err().expect("should fail").kind
    }

    #[test]
    fn parses_lines_header() {
        let text = format!("#ssenc1 lines ws=0 pad=4096\r\n{}\r\nbody\n", pw_slot());
        let f = parse_file(text.as_bytes()).unwrap();
        assert_eq!((f.mode, f.ws, f.pad), (Mode::Lines, false, 4096));
        assert_eq!(f.header_line, "#ssenc1 lines ws=0 pad=4096");
        assert_eq!(f.slot_lines, vec![pw_slot()]);
        assert_eq!(f.body, b"body\n");
        assert!(f.seal.is_none());
    }

    #[test]
    fn parses_blob_header_without_final_lf() {
        let text = format!("#ssenc1 blob chunk=1048576\n{}", pw_slot());
        let f = parse_file(text.as_bytes()).unwrap();
        assert_eq!((f.mode, f.chunk), (Mode::Blob, 1_048_576));
        assert_eq!(f.body, b"");
    }

    #[test]
    fn rejects_bad_headers() {
        let s = pw_slot();
        for bad in [
            String::new(),
            "hello\n".to_string(),
            "#ssenc1\n".to_string(),
            format!("#ssenc2 lines ws=1 pad=16\n{s}\n"),
            format!("#ssenc1 lines ws=2 pad=16\n{s}\n"),
            format!("#ssenc1 lines ws=1 pad=016\n{s}\n"),
            format!("#ssenc1 lines ws=1 pad=4097\n{s}\n"),
            format!("#ssenc1 lines ws=1 pad=16 \n{s}\n"),
            format!("#ssenc1 lines  ws=1 pad=16\n{s}\n"),
            format!("#ssenc1 lines ws=1 pad=16\r\r\n{s}\n"),
            format!("#ssenc1 blob chunk=0\n{s}\n"),
            format!("#ssenc1 blob chunk=1048577\n{s}\n"),
            format!("#ssenc1 blob chunk=65536\n{s}\n#seal {}\n", "A".repeat(43)),
            "#ssenc1 lines ws=1 pad=16\n".to_string(),
            "#ssenc1 lines ws=1 pad=16\nbody\n".to_string(),
            format!("#ssenc1 lines ws=1 pad=16\n#slot pw argon2id m=8192,t=1,p=1 {SALT} AAAA\n"),
            format!("#ssenc1 lines ws=1 pad=16\n#slot pw argon2id m=7,t=1,p=1 {SALT} {WRAPPED}\n"),
            format!("#ssenc1 lines ws=1 pad=16\n#slot pw argon2id m=8192,t=65,p=1 {SALT} {WRAPPED}\n"),
            format!("#ssenc1 lines ws=1 pad=16\n#slot pw argon2id m=8192,t=1,p=17 {SALT} {WRAPPED}\n"),
            format!("#ssenc1 lines ws=1 pad=16\n#slot pw scrypt m=8192,t=1,p=1 {SALT} {WRAPPED}\n"),
            format!(
                "#ssenc1 lines ws=1 pad=16\n#slot ssh ecdsa-sha2-nistp256 SHA256:{} {SALT} {WRAPPED}\n",
                "A".repeat(43)
            ),
            format!("#ssenc1 lines ws=1 pad=16\n{s}\n#seal AAAA\n"),
            format!("#ssenc1 lines ws=1 pad=16\n{s}\n#seal {0}\n#seal {0}\n", "A".repeat(43)),
            format!("#ssenc1 lines ws=1 pad=16\n{s}\n#seal {}\n{s}\n", "A".repeat(43)),
        ] {
            assert_eq!(kind(&bad), ErrorKind::Malformed, "{bad:?}");
        }
    }

    #[test]
    fn parses_ssh_slot_and_seal() {
        let fp = format!("SHA256:{}", "a+/".repeat(14) + "b");
        let salt = "A".repeat(43);
        let text = format!(
            "#ssenc1 lines ws=1 pad=0\n{}\n#slot ssh ssh-rsa {fp} {salt} {WRAPPED}\n#seal {salt}\n\n#slot not a slot\n",
            pw_slot()
        );
        let f = parse_file(text.as_bytes()).unwrap();
        assert_eq!(f.slots.len(), 2);
        assert!(
            matches!(&f.slots[1], Slot::Ssh { key_type, fingerprint, .. } if key_type == "ssh-rsa" && *fingerprint == fp)
        );
        assert_eq!(f.seal.as_deref(), Some(&[0u8; 32][..]));
        assert_eq!(f.body, b"\n#slot not a slot\n");
    }

    #[test]
    fn kdf_profiles() {
        assert_eq!(parse_kdf(None).unwrap(), KdfParams::DEFAULT);
        assert_eq!(parse_kdf(Some(&"strong".into())).unwrap(), KdfParams::STRONG);
        assert_eq!(
            parse_kdf(Some(&"m=8192,t=1,p=1".into())).unwrap(),
            KdfParams { m: 8192, t: 1, p: 1 }
        );
        for bad in [
            "",
            "fast",
            "m=8192,t=1",
            "m=08192,t=1,p=1",
            "m=8192,t=1,p=1,",
            "m=8192, t=1,p=1",
            "m=7,t=1,p=1",
            "m=8192,t=65,p=1",
            "m=8192,t=1,p=17",
            "m=4194305,t=1,p=1",
            "t=1,m=8192,p=1",
        ] {
            assert_eq!(
                parse_kdf(Some(&bad.into())).unwrap_err().kind,
                ErrorKind::Usage,
                "{bad}"
            );
        }
        assert_eq!(
            parse_kdf(Some(&KdfParams { m: 8, t: 1, p: 2 }.into()))
                .unwrap_err()
                .kind,
            ErrorKind::Usage
        );
    }
}
