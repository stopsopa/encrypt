//! Errors and byte helpers.

use std::fmt;

/// The four error kinds of SPEC.md section 6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Bad arguments, empty password, no key given.
    Usage,
    /// No slot opens with the key; a tag or the seal does not verify.
    Auth,
    /// Not an ssenc1 file, bad header, bad base64, bad padding, out-of-range parameter.
    Malformed,
    /// ssh-agent unreachable, key not in agent, unsupported key type.
    Env,
}

impl ErrorKind {
    /// The name used on stderr: `USAGE`, `AUTH`, `MALFORMED` or `ENV`.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorKind::Usage => "USAGE",
            ErrorKind::Auth => "AUTH",
            ErrorKind::Malformed => "MALFORMED",
            ErrorKind::Env => "ENV",
        }
    }

    /// The CLI exit code: 1, 2, 3 or 4.
    pub fn exit_code(self) -> i32 {
        match self {
            ErrorKind::Usage => 1,
            ErrorKind::Auth => 2,
            ErrorKind::Malformed => 3,
            ErrorKind::Env => 4,
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Every failure of this library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub message: String,
}

impl Error {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Error {
            kind,
            message: message.into(),
        }
    }
    pub(crate) fn usage(message: impl Into<String>) -> Self {
        Error::new(ErrorKind::Usage, message)
    }
    pub(crate) fn auth(message: impl Into<String>) -> Self {
        Error::new(ErrorKind::Auth, message)
    }
    pub(crate) fn malformed(message: impl Into<String>) -> Self {
        Error::new(ErrorKind::Malformed, message)
    }
    pub(crate) fn env(message: impl Into<String>) -> Self {
        Error::new(ErrorKind::Env, message)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

pub(crate) fn ssh_string(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + b.len());
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
    out
}

/// Reads an SSH wire string at `off`; returns it and the offset after it.
pub(crate) fn ssh_read_string(b: &[u8], off: usize) -> Option<(&[u8], usize)> {
    let head = b.get(off..off.checked_add(4)?)?;
    let len = u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as usize;
    let end = (off + 4).checked_add(len)?;
    Some((b.get(off + 4..end)?, end))
}

/// Bytes to text the way the reference does it: one char per byte (Latin-1).
pub(crate) fn latin1(b: &[u8]) -> String {
    if b.is_ascii() {
        // ASCII is valid UTF-8, byte for byte.
        return String::from_utf8_lossy(b).into_owned();
    }
    b.iter().map(|&c| c as char).collect()
}

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B64STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const fn b64url_rev() -> [i8; 256] {
    let mut t = [-1i8; 256];
    let mut i = 0;
    while i < 64 {
        t[B64URL[i] as usize] = i as i8;
        i += 1;
    }
    t
}
const B64URL_REV: [i8; 256] = b64url_rev();

fn b64_encode_with(alphabet: &[u8; 64], b: &[u8]) -> String {
    let mut out = Vec::with_capacity(b.len().div_ceil(3) * 4);
    let (chunks, rest) = b.as_chunks::<3>();
    for c in chunks {
        let v = (c[0] as u32) << 16 | (c[1] as u32) << 8 | c[2] as u32;
        out.push(alphabet[(v >> 18) as usize]);
        out.push(alphabet[(v >> 12 & 63) as usize]);
        out.push(alphabet[(v >> 6 & 63) as usize]);
        out.push(alphabet[(v & 63) as usize]);
    }
    match *rest {
        [a] => {
            let v = (a as u32) << 16;
            out.push(alphabet[(v >> 18) as usize]);
            out.push(alphabet[(v >> 12 & 63) as usize]);
        }
        [a, b] => {
            let v = (a as u32) << 16 | (b as u32) << 8;
            out.push(alphabet[(v >> 18) as usize]);
            out.push(alphabet[(v >> 12 & 63) as usize]);
            out.push(alphabet[(v >> 6 & 63) as usize]);
        }
        _ => {}
    }
    // Only alphabet bytes were pushed, all ASCII.
    String::from_utf8(out).expect("base64 output is ASCII")
}

/// RFC 4648 section 5 base64url without padding.
pub fn b64url_encode(b: &[u8]) -> String {
    b64_encode_with(B64URL, b)
}

/// Standard base64 without padding (ssh fingerprints).
pub(crate) fn b64std_encode_nopad(b: &[u8]) -> String {
    b64_encode_with(B64STD, b)
}

/// Decodes unpadded base64url; `None` when it is not valid.
///
/// Like the reference implementation this does not reject non-zero trailing bits.
pub fn b64url_decode(s: &[u8]) -> Option<Vec<u8>> {
    let n = s.len();
    if n % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(n / 4 * 3 + 3);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &c in s {
        let v = B64URL_REV[c as usize];
        if v < 0 {
            return None;
        }
        acc = (acc << 6 | v as u32) & 0xff_ffff;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// Standard base64, with or without padding; used only for ssh public key lines.
/// (As in the reference, the url-safe characters are accepted as well.)
pub(crate) fn b64std_decode(s: &str) -> Option<Vec<u8>> {
    let t: Vec<u8> = s
        .trim_end_matches('=')
        .bytes()
        .map(|c| match c {
            b'+' => b'-',
            b'/' => b'_',
            c => c,
        })
        .collect();
    b64url_decode(&t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_roundtrip_all_lengths() {
        let data: Vec<u8> = (0..=255u8).collect();
        for n in 0..data.len() {
            let e = b64url_encode(&data[..n]);
            assert!(!e.contains('='));
            assert_eq!(b64url_decode(e.as_bytes()).unwrap(), &data[..n]);
        }
    }

    #[test]
    fn b64url_known_values() {
        assert_eq!(b64url_encode(b""), "");
        assert_eq!(b64url_encode(b"f"), "Zg");
        assert_eq!(b64url_encode(b"fo"), "Zm8");
        assert_eq!(b64url_encode(b"foo"), "Zm9v");
        assert_eq!(b64url_encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(b64std_encode_nopad(&[0xfb, 0xff]), "+/8");
    }

    #[test]
    fn b64url_rejects_invalid() {
        assert!(b64url_decode(b"A").is_none());
        assert!(b64url_decode(b"AAAAA").is_none());
        assert!(b64url_decode(b"Zg==").is_none());
        assert!(b64url_decode(b"Zm+v").is_none());
        assert!(b64url_decode(b"Zm9\xff").is_none());
        assert!(b64url_decode(b"Zm 9").is_none());
        assert_eq!(b64url_decode(b"").unwrap(), b"");
    }

    #[test]
    fn b64std_accepts_padding() {
        assert_eq!(b64std_decode("Zg==").unwrap(), b"f");
        assert_eq!(b64std_decode("+/8=").unwrap(), [0xfb, 0xff]);
    }

    #[test]
    fn ssh_strings() {
        let s = ssh_string(b"abc");
        assert_eq!(s, [0, 0, 0, 3, b'a', b'b', b'c']);
        assert_eq!(ssh_read_string(&s, 0), Some((&b"abc"[..], 7)));
        assert_eq!(ssh_read_string(&s[..6], 0), None);
        assert_eq!(ssh_read_string(&s, 5), None);
    }
}
