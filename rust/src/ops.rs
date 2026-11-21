//! Key slots, lines mode, blob mode and the four operations (SPEC.md sections 3 to 5).

use crate::agent::{agent_find_key, agent_sign};
use crate::format::{
    header_line_for, parse_file, parse_kdf, pw_slot_line, ssh_slot_line, Kdf, KdfParams, Mode, ParsedFile, Slot,
};
use crate::prim::{argon2id, constant_time_equal, hkdf32, hmac_sha256, random_bytes, Secret32, SivKey};
use crate::ssh::{ssh_fingerprint, ssh_kek, ssh_key_type, ssh_parse_public_key, ssh_require_supported, SshSigner};
use crate::util::{b64url_decode, b64url_encode, latin1, Error, ErrorKind};
use std::sync::Arc;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------------------
// public types
// ---------------------------------------------------------------------------------------

/// A key that opens, or is given access to, an encrypted text.
#[derive(Clone)]
pub enum Key {
    /// The raw password bytes; no normalisation is applied. Must not be empty.
    Password { password: Vec<u8> },
    Ssh {
        /// Content of an OpenSSH public key file (`ssh-ed25519 AAAA... comment`).
        public_key: Option<String>,
        /// `SHA256:...` fingerprint of a key loaded in ssh-agent; used when `public_key` is `None`.
        fingerprint: Option<String>,
        /// Path of the agent socket; default is `$SSH_AUTH_SOCK`.
        agent_socket: Option<String>,
        /// Replaces ssh-agent as the source of the signature.
        signer: Option<SshSigner>,
    },
}

impl Key {
    pub fn password(password: impl Into<Vec<u8>>) -> Key {
        Key::Password {
            password: password.into(),
        }
    }

    /// An ssh key given as the content of its public key file, signed for by ssh-agent.
    pub fn ssh_public_key(text: impl Into<String>) -> Key {
        Key::Ssh {
            public_key: Some(text.into()),
            fingerprint: None,
            agent_socket: None,
            signer: None,
        }
    }

    /// An ssh key loaded in ssh-agent, named by its `SHA256:...` fingerprint.
    pub fn ssh_fingerprint(fingerprint: impl Into<String>) -> Key {
        Key::Ssh {
            public_key: None,
            fingerprint: Some(fingerprint.into()),
            agent_socket: None,
            signer: None,
        }
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Key::Password { .. } => f.write_str("Key::Password { .. }"),
            Key::Ssh {
                public_key,
                fingerprint,
                agent_socket,
                signer,
            } => f
                .debug_struct("Key::Ssh")
                .field("public_key", public_key)
                .field("fingerprint", fingerprint)
                .field("agent_socket", agent_socket)
                .field("signer", &signer.as_ref().map(|_| "<callback>"))
                .finish(),
        }
    }
}

/// Options of [`encrypt`]. `None` means "the default", or with `previous` "as in `previous`".
#[derive(Debug, Clone, Default)]
pub struct EncryptOptions {
    /// `Lines` (default) encrypts line by line; `Blob` encrypts the input as a whole.
    pub mode: Option<Mode>,
    /// Lines mode: keep leading and trailing spaces/tabs of every line in clear. Default true.
    pub preserve_whitespace: Option<bool>,
    /// Lines mode: pad every line to a multiple of this many bytes; 0 disables. Default 16.
    pub pad: Option<u64>,
    /// Blob mode: chunk size in bytes. Default 65536.
    pub chunk: Option<u64>,
    /// Argon2id cost for password slots. Default [`KdfParams::DEFAULT`].
    pub kdf: Option<Kdf>,
    /// Previous encrypted version: its data key and slots are reused, so unchanged lines stay identical.
    pub previous: Option<Vec<u8>>,
    /// Lines mode: add a MAC over the whole file. Default false.
    pub seal: Option<bool>,
}

/// Options of [`rekey`].
#[derive(Debug, Clone)]
pub struct RekeyOptions {
    /// true (default): re-encrypt everything under a new data key. false: only rewrap the data key.
    pub rotate_data_key: bool,
    pub kdf: Option<Kdf>,
}

impl Default for RekeyOptions {
    fn default() -> Self {
        RekeyOptions {
            rotate_data_key: true,
            kdf: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotInfo {
    Pw { m: u32, t: u32, p: u32 },
    Ssh { key_type: String, fingerprint: String },
}

/// What [`inspect`] reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InspectResult {
    Lines {
        ws: bool,
        pad: usize,
        seal: bool,
        slots: Vec<SlotInfo>,
    },
    Blob {
        chunk: usize,
        slots: Vec<SlotInfo>,
    },
}

impl InspectResult {
    /// The single-line JSON form of SPEC.md section 5 (without the trailing LF).
    pub fn to_json(&self) -> String {
        let slots_json = |slots: &[SlotInfo]| {
            let items: Vec<String> = slots
                .iter()
                .map(|s| match s {
                    SlotInfo::Pw { m, t, p } => {
                        format!(r#"{{"type":"pw","kdf":"argon2id","m":{m},"t":{t},"p":{p}}}"#)
                    }
                    // Both fields were checked against a strict character set when parsed.
                    SlotInfo::Ssh { key_type, fingerprint } => {
                        format!(r#"{{"type":"ssh","keyType":"{key_type}","fingerprint":"{fingerprint}"}}"#)
                    }
                })
                .collect();
            format!("[{}]", items.join(","))
        };
        match self {
            InspectResult::Lines { ws, pad, seal, slots } => format!(
                r#"{{"format":"ssenc1","mode":"lines","ws":{ws},"pad":{pad},"seal":{seal},"slots":{}}}"#,
                slots_json(slots)
            ),
            InspectResult::Blob { chunk, slots } => {
                format!(
                    r#"{{"format":"ssenc1","mode":"blob","chunk":{chunk},"slots":{}}}"#,
                    slots_json(slots)
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// key slots
// ---------------------------------------------------------------------------------------

const SLOT_AD: &[u8] = b"ssenc1/slot";

fn password_bytes(password: &[u8]) -> Result<&[u8], Error> {
    if password.is_empty() {
        return Err(Error::usage("password must not be empty"));
    }
    Ok(password)
}

struct ResolvedSsh {
    blob: Vec<u8>,
    key_type: String,
    fingerprint: String,
    signer: SshSigner,
}

fn resolve_ssh(
    public_key: &Option<String>,
    fingerprint: &Option<String>,
    agent_socket: &Option<String>,
    signer: &Option<SshSigner>,
) -> Result<ResolvedSsh, Error> {
    let blob = match (public_key, fingerprint) {
        (Some(text), _) => ssh_parse_public_key(text)?,
        (None, Some(fp)) => agent_find_key(agent_socket.as_deref(), fp)?,
        (None, None) => return Err(Error::usage("ssh key needs 'publicKey' or 'fingerprint'")),
    };
    let key_type = ssh_key_type(&blob)?;
    ssh_require_supported(&key_type)?;
    let signer = match signer {
        Some(s) => s.clone(),
        None => {
            let socket = agent_socket.clone();
            Arc::new(move |b: &[u8], d: &[u8]| agent_sign(socket.as_deref(), b, d))
        }
    };
    let fingerprint = ssh_fingerprint(&blob);
    Ok(ResolvedSsh {
        blob,
        key_type,
        fingerprint,
        signer,
    })
}

fn wrap_dek(kek: &[u8; 32], dek: &[u8; 32]) -> Vec<u8> {
    SivKey::derive(kek, "wrap").encrypt(SLOT_AD, dek)
}

fn make_slots(keys: &[Key], dek: &[u8; 32], kdf: KdfParams) -> Result<Vec<String>, Error> {
    if keys.is_empty() {
        return Err(Error::usage("at least one key is required"));
    }
    let mut lines = Vec::new();
    for key in keys {
        if let Key::Password { password } = key {
            let salt: [u8; 16] = random_bytes()?;
            let kek = Zeroizing::new(argon2id(password_bytes(password)?, &salt, kdf.m, kdf.t, kdf.p)?);
            lines.push(pw_slot_line(kdf, &salt, &wrap_dek(&kek, dek)));
        }
    }
    for key in keys {
        if let Key::Ssh {
            public_key,
            fingerprint,
            agent_socket,
            signer,
        } = key
        {
            let r = resolve_ssh(public_key, fingerprint, agent_socket, signer)?;
            let salt: [u8; 32] = random_bytes()?;
            let kek = Zeroizing::new(ssh_kek(&r.blob, &salt, &r.signer)?);
            lines.push(ssh_slot_line(&r.key_type, &r.fingerprint, &salt, &wrap_dek(&kek, dek)));
        }
    }
    Ok(lines)
}

fn try_unwrap(kek: &[u8; 32], wrapped: &[u8]) -> Result<Option<Secret32>, Error> {
    match SivKey::derive(kek, "wrap").decrypt(SLOT_AD, wrapped) {
        Ok(dek) => {
            let dek = Zeroizing::new(dek);
            // Slots are parsed with exactly 48 bytes, so this is always 32 bytes.
            let mut out = Zeroizing::new([0u8; 32]);
            out.copy_from_slice(&dek);
            Ok(Some(out))
        }
        Err(e) if e.kind == ErrorKind::Auth => Ok(None),
        Err(e) => Err(e),
    }
}

/// Returns the data key, or `None` when no slot opens with this key.
fn open_with(file: &ParsedFile, key: &Key) -> Result<Option<Secret32>, Error> {
    match key {
        Key::Password { password } => {
            let pw = password_bytes(password)?;
            for slot in &file.slots {
                if let Slot::Pw { kdf, salt, wrapped } = slot {
                    let kek = Zeroizing::new(argon2id(pw, salt, kdf.m, kdf.t, kdf.p)?);
                    if let Some(dek) = try_unwrap(&kek, wrapped)? {
                        return Ok(Some(dek));
                    }
                }
            }
            Ok(None)
        }
        Key::Ssh {
            public_key,
            fingerprint,
            agent_socket,
            signer,
        } => {
            let r = resolve_ssh(public_key, fingerprint, agent_socket, signer)?;
            for slot in &file.slots {
                if let Slot::Ssh {
                    fingerprint,
                    salt,
                    wrapped,
                    ..
                } = slot
                {
                    if *fingerprint != r.fingerprint {
                        continue;
                    }
                    let kek = Zeroizing::new(ssh_kek(&r.blob, salt, &r.signer)?);
                    if let Some(dek) = try_unwrap(&kek, wrapped)? {
                        return Ok(Some(dek));
                    }
                }
            }
            Ok(None)
        }
    }
}

fn open_or_fail(file: &ParsedFile, keys: &[Key]) -> Result<Secret32, Error> {
    if keys.is_empty() {
        return Err(Error::usage("at least one key is required"));
    }
    for key in keys {
        if let Some(dek) = open_with(file, key)? {
            return Ok(dek);
        }
    }
    Err(Error::auth("no key slot could be opened with the given key"))
}

// ---------------------------------------------------------------------------------------
// lines mode (SPEC.md section 3)
// ---------------------------------------------------------------------------------------

fn is_ws(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

/// One line of `data`: `data[start..end]` is the content, `data[end..next]` the terminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Span {
    start: usize,
    end: usize,
    next: usize,
}

pub(crate) fn line_spans(data: &[u8]) -> Vec<Span> {
    let mut spans = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        match data[pos..].iter().position(|&c| c == b'\n') {
            None => {
                spans.push(Span {
                    start: pos,
                    end: data.len(),
                    next: data.len(),
                });
                break;
            }
            Some(i) => {
                let lf = pos + i;
                let end = if lf > pos && data[lf - 1] == b'\r' { lf - 1 } else { lf };
                spans.push(Span {
                    start: pos,
                    end,
                    next: lf + 1,
                });
                pos = lf + 1;
            }
        }
    }
    spans
}

/// The content `[s, e)` of a line without its leading and trailing spaces and tabs.
pub(crate) fn core_of(data: &[u8], span: Span) -> (usize, usize) {
    let (mut s, mut e) = (span.start, span.end);
    while s < e && is_ws(data[s]) {
        s += 1;
    }
    while e > s && is_ws(data[e - 1]) {
        e -= 1;
    }
    (s, e)
}

pub(crate) fn pad_line(x: &[u8], pad: usize) -> Vec<u8> {
    let mut out = x.to_vec();
    if let Some(blocks) = x.len().checked_div(pad) {
        out.push(0x80);
        out.resize((blocks + 1) * pad, 0);
    }
    out
}

pub(crate) fn unpad_line(mut x: Vec<u8>, pad: usize) -> Result<Vec<u8>, Error> {
    if pad == 0 {
        return Ok(x);
    }
    let mut n = x.len();
    while n > 0 && x[n - 1] == 0 {
        n -= 1;
    }
    if n == 0 || x[n - 1] != 0x80 {
        return Err(Error::malformed("invalid line padding"));
    }
    x.truncate(n - 1);
    Ok(x)
}

fn encrypt_lines(dek: &[u8; 32], ws: bool, pad: usize, plain: &[u8]) -> Vec<u8> {
    let key = SivKey::derive(dek, "line");
    let mut out = Vec::with_capacity(plain.len() * 2 + 64);
    for span in line_spans(plain) {
        let (s, e) = if ws {
            core_of(plain, span)
        } else {
            (span.start, span.end)
        };
        if ws && s == e {
            out.extend_from_slice(&plain[span.start..span.next]);
            continue;
        }
        let padded = Zeroizing::new(pad_line(&plain[s..e], pad));
        out.extend_from_slice(&plain[span.start..s]);
        out.extend_from_slice(b64url_encode(&key.encrypt(b"", &padded)).as_bytes());
        out.extend_from_slice(&plain[e..span.next]);
    }
    out
}

fn decrypt_lines(dek: &[u8; 32], pad: usize, body: &[u8]) -> Result<Vec<u8>, Error> {
    let key = SivKey::derive(dek, "line");
    let mut out = Vec::with_capacity(body.len());
    for (i, span) in line_spans(body).into_iter().enumerate() {
        let (s, e) = core_of(body, span);
        if s == e {
            out.extend_from_slice(&body[span.start..span.next]);
            continue;
        }
        let raw = match b64url_decode(&body[s..e]) {
            Some(raw) if raw.len() >= 16 => raw,
            _ => {
                return Err(Error::malformed(format!(
                    "line {} is not a valid encrypted line",
                    i + 1
                )))
            }
        };
        let plain = unpad_line(key.decrypt(b"", &raw)?, pad)?;
        out.extend_from_slice(&body[span.start..s]);
        out.extend_from_slice(&plain);
        out.extend_from_slice(&body[e..span.next]);
    }
    Ok(out)
}

fn seal_for(dek: &[u8; 32], header_line: &str, body: &[u8]) -> [u8; 32] {
    let k = Zeroizing::new(hkdf32(dek, None, b"ssenc1/seal"));
    hmac_sha256(&k[..], &[header_line.as_bytes(), b"\n", body])
}

// ---------------------------------------------------------------------------------------
// blob mode (SPEC.md section 4)
// ---------------------------------------------------------------------------------------

fn blob_ad(index: usize, last: bool) -> [u8; 9] {
    let mut ad = [0u8; 9];
    ad[..8].copy_from_slice(&(index as u64).to_be_bytes());
    ad[8] = last as u8;
    ad
}

fn encrypt_blob(dek: &[u8; 32], chunk: usize, plain: &[u8]) -> Vec<u8> {
    let key = SivKey::derive(dek, "blob");
    let count = plain.len().div_ceil(chunk).max(1);
    let mut records = Vec::with_capacity(plain.len() + count * 16);
    for i in 0..count {
        let piece = &plain[(i * chunk).min(plain.len())..((i + 1) * chunk).min(plain.len())];
        records.extend_from_slice(&key.encrypt(&blob_ad(i, i == count - 1), piece));
    }
    let b64 = b64url_encode(&records);
    let mut out = Vec::with_capacity(b64.len() + b64.len() / 76 + 1);
    for line in b64.as_bytes().chunks(76) {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out
}

fn decrypt_blob(dek: &[u8; 32], chunk: usize, body: &[u8]) -> Result<Vec<u8>, Error> {
    let compact: Vec<u8> = body
        .iter()
        .copied()
        .filter(|c| !matches!(c, b'\n' | b'\r' | b' ' | b'\t'))
        .collect();
    let raw = match b64url_decode(&compact) {
        Some(raw) if !raw.is_empty() => raw,
        _ => return Err(Error::malformed("blob body is not valid base64url")),
    };
    let key = SivKey::derive(dek, "blob");
    let count = raw.len().div_ceil(chunk + 16);
    let mut out = Vec::with_capacity(raw.len());
    for (i, record) in raw.chunks(chunk + 16).enumerate() {
        out.extend_from_slice(&key.decrypt(&blob_ad(i, i == count - 1), record)?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------
// operations (SPEC.md section 5)
// ---------------------------------------------------------------------------------------

struct Layout {
    mode: Mode,
    ws: bool,
    pad: u64,
    chunk: u64,
    seal: bool,
}

fn check_layout(l: &Layout) -> Result<(), Error> {
    if l.pad > 4096 {
        return Err(Error::usage("pad must be an integer from 0 to 4096"));
    }
    if l.chunk < 1 || l.chunk > 1_048_576 {
        return Err(Error::usage("chunk must be an integer from 1 to 1048576"));
    }
    if l.seal && l.mode != Mode::Lines {
        return Err(Error::usage("seal is only available in lines mode"));
    }
    Ok(())
}

fn assemble(dek: &[u8; 32], slot_lines: &[String], l: &Layout, plain: &[u8]) -> String {
    // check_layout() bounded both numbers.
    let (pad, chunk) = (l.pad as usize, l.chunk as usize);
    let header_line = header_line_for(l.mode, l.ws, pad, chunk);
    let body = match l.mode {
        Mode::Lines => encrypt_lines(dek, l.ws, pad, plain),
        Mode::Blob => encrypt_blob(dek, chunk, plain),
    };
    let mut out = String::with_capacity(body.len() + 256);
    out.push_str(&header_line);
    out.push('\n');
    for s in slot_lines {
        out.push_str(s);
        out.push('\n');
    }
    if l.seal {
        out.push_str("#seal ");
        out.push_str(&b64url_encode(&seal_for(dek, &header_line, &body)));
        out.push('\n');
    }
    out.push_str(&latin1(&body));
    out
}

fn decrypt_parsed(file: &ParsedFile, dek: &[u8; 32]) -> Result<Vec<u8>, Error> {
    if let Some(seal) = &file.seal {
        if !constant_time_equal(seal, &seal_for(dek, &file.header_line, file.body)) {
            return Err(Error::auth(
                "seal does not match: lines were added, removed, reordered or modified",
            ));
        }
    }
    match file.mode {
        Mode::Lines => decrypt_lines(dek, file.pad, file.body),
        Mode::Blob => decrypt_blob(dek, file.chunk, file.body),
    }
}

/// Encrypts bytes to ssenc1 ASCII text.
///
/// One slot is made per key (password slots first, then ssh slots). With
/// `opts.previous` the data key and slots of that text are reused instead; any of `keys`
/// that opens it will do.
pub fn encrypt(input: &[u8], keys: &[Key], opts: &EncryptOptions) -> Result<String, Error> {
    if let Some(previous) = &opts.previous {
        let prev = parse_file(previous)?;
        let dek = open_or_fail(&prev, keys)?;
        let mode = opts.mode.unwrap_or(prev.mode);
        let prev_lines = prev.mode == Mode::Lines;
        let layout = Layout {
            mode,
            ws: opts
                .preserve_whitespace
                .unwrap_or(if prev_lines { prev.ws } else { true }),
            pad: opts.pad.unwrap_or(if prev_lines { prev.pad as u64 } else { 16 }),
            chunk: opts.chunk.unwrap_or(if prev_lines { 65536 } else { prev.chunk as u64 }),
            seal: opts.seal.unwrap_or(mode == Mode::Lines && prev.seal.is_some()),
        };
        check_layout(&layout)?;
        return Ok(assemble(&dek, &prev.slot_lines, &layout, input));
    }
    let layout = Layout {
        mode: opts.mode.unwrap_or(Mode::Lines),
        ws: opts.preserve_whitespace.unwrap_or(true),
        pad: opts.pad.unwrap_or(16),
        chunk: opts.chunk.unwrap_or(65536),
        seal: opts.seal.unwrap_or(false),
    };
    check_layout(&layout)?;
    let kdf = parse_kdf(opts.kdf.as_ref())?;
    let dek: Secret32 = Zeroizing::new(random_bytes()?);
    let slots = make_slots(keys, &dek, kdf)?;
    Ok(assemble(&dek, &slots, &layout, input))
}

/// Decrypts ssenc1 text and returns the original bytes.
pub fn decrypt(input: &[u8], key: &Key) -> Result<Vec<u8>, Error> {
    let file = parse_file(input)?;
    let dek = open_or_fail(&file, std::slice::from_ref(key))?;
    decrypt_parsed(&file, &dek)
}

/// Replaces the keys of an encrypted text.
pub fn rekey(input: &[u8], old_key: &Key, new_keys: &[Key], opts: &RekeyOptions) -> Result<String, Error> {
    let file = parse_file(input)?;
    let dek = open_or_fail(&file, std::slice::from_ref(old_key))?;
    let kdf = parse_kdf(opts.kdf.as_ref())?;
    if !opts.rotate_data_key {
        let slots = make_slots(new_keys, &dek, kdf)?;
        let mut out = String::with_capacity(input.len() + 256);
        out.push_str(&file.header_line);
        out.push('\n');
        for s in &slots {
            out.push_str(s);
            out.push('\n');
        }
        if let Some(seal) = &file.seal {
            out.push_str("#seal ");
            out.push_str(&b64url_encode(seal));
            out.push('\n');
        }
        out.push_str(&latin1(file.body));
        return Ok(out);
    }
    let plain = Zeroizing::new(decrypt_parsed(&file, &dek)?);
    let lines = file.mode == Mode::Lines;
    let layout = Layout {
        mode: file.mode,
        ws: file.ws,
        pad: if lines { file.pad as u64 } else { 16 },
        chunk: if lines { 65536 } else { file.chunk as u64 },
        seal: file.seal.is_some(),
    };
    let new_dek: Secret32 = Zeroizing::new(random_bytes()?);
    let slots = make_slots(new_keys, &new_dek, kdf)?;
    Ok(assemble(&new_dek, &slots, &layout, &plain))
}

/// Describes an encrypted text without needing a key.
pub fn inspect(input: &[u8]) -> Result<InspectResult, Error> {
    let file = parse_file(input)?;
    let slots = file
        .slots
        .iter()
        .map(|s| match s {
            Slot::Pw { kdf, .. } => SlotInfo::Pw {
                m: kdf.m,
                t: kdf.t,
                p: kdf.p,
            },
            Slot::Ssh {
                key_type, fingerprint, ..
            } => SlotInfo::Ssh {
                key_type: key_type.clone(),
                fingerprint: fingerprint.clone(),
            },
        })
        .collect();
    Ok(match file.mode {
        Mode::Lines => InspectResult::Lines {
            ws: file.ws,
            pad: file.pad,
            seal: file.seal.is_some(),
            slots,
        },
        Mode::Blob => InspectResult::Blob {
            chunk: file.chunk,
            slots,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::ssh_string;

    const DEK: [u8; 32] = [7; 32];

    fn cheap() -> EncryptOptions {
        EncryptOptions {
            kdf: Some("m=64,t=1,p=1".into()),
            ..Default::default()
        }
    }

    fn pw(p: &str) -> Key {
        Key::password(p)
    }

    fn spans(data: &[u8]) -> Vec<(usize, usize, usize)> {
        line_spans(data).into_iter().map(|s| (s.start, s.end, s.next)).collect()
    }

    fn body_of(text: &str) -> &str {
        let f = parse_file(text.as_bytes()).unwrap();
        &text[text.len() - f.body.len()..]
    }

    #[test]
    fn line_splitting() {
        assert_eq!(spans(b""), vec![]);
        assert_eq!(spans(b"\n"), vec![(0, 0, 1)]);
        assert_eq!(spans(b"a"), vec![(0, 1, 1)]);
        assert_eq!(spans(b"a\n"), vec![(0, 1, 2)]);
        assert_eq!(spans(b"a\nb"), vec![(0, 1, 2), (2, 3, 3)]);
        assert_eq!(spans(b"a\r\nb\r\n"), vec![(0, 1, 3), (3, 4, 6)]);
        assert_eq!(spans(b"\r\n\n"), vec![(0, 0, 2), (2, 2, 3)]);
        // A lone CR is content; CR CR LF keeps the first CR as content.
        assert_eq!(spans(b"a\rb\n"), vec![(0, 3, 4)]);
        assert_eq!(spans(b"a\r\r\n"), vec![(0, 2, 4)]);
        assert_eq!(spans(b"a\r"), vec![(0, 2, 2)]);
    }

    #[test]
    fn whitespace_core() {
        let core = |d: &[u8]| core_of(d, line_spans(d)[0]);
        assert_eq!(core(b"  a b\t \n"), (2, 5));
        assert_eq!(core(b" \t \n"), (3, 3));
        assert_eq!(core(b"x"), (0, 1));
        // Only SP and TAB count; CR, VT, FF and NBSP are content.
        assert_eq!(core(b" \x0b \n"), (1, 2));
        assert_eq!(core(b" \r \r\n"), (1, 2));
    }

    #[test]
    fn padding() {
        assert_eq!(pad_line(b"abc", 0), b"abc");
        assert_eq!(pad_line(b"", 0), b"");
        assert_eq!(pad_line(b"", 1), [0x80]);
        assert_eq!(pad_line(b"abc", 1), b"abc\x80");
        assert_eq!(pad_line(b"abc", 4), b"abc\x80");
        assert_eq!(pad_line(b"abcd", 4), b"abcd\x80\0\0\0");
        assert_eq!(pad_line(b"", 16).len(), 16);
        assert_eq!(pad_line(&[0; 15], 16).len(), 16);
        assert_eq!(pad_line(&[0; 16], 16).len(), 32);
        for pad in [1usize, 2, 16, 4096] {
            for len in [0usize, 1, 15, 16, 17, 4095, 4096] {
                let x = vec![0x80u8; len];
                let p = pad_line(&x, pad);
                assert_eq!(p.len() % pad, 0);
                assert!(p.len() > len && p.len() <= len + pad);
                assert_eq!(unpad_line(p, pad).unwrap(), x);
            }
        }
        assert_eq!(unpad_line(b"abc".to_vec(), 0).unwrap(), b"abc");
        // Plaintext ending in zero bytes survives.
        assert_eq!(unpad_line(pad_line(b"a\0\0", 4), 4).unwrap(), b"a\0\0");
        for bad in [&b""[..], b"\0\0\0\0", b"abcd", b"abc\x81"] {
            assert_eq!(unpad_line(bad.to_vec(), 4).unwrap_err().kind, ErrorKind::Malformed);
        }
    }

    #[test]
    fn lines_ws_on_keeps_whitespace_and_blank_lines() {
        let plain = b"  key: value\t\n\n \t \r\n\tlast";
        let body = encrypt_lines(&DEK, true, 16, plain);
        let lines: Vec<&[u8]> = body.split(|&c| c == b'\n').collect();
        assert_eq!(lines.len(), 4);
        assert!(lines[0].starts_with(b"  ") && lines[0].ends_with(b"\t"));
        assert_eq!(lines[0].len(), 2 + 43 + 1); // 16 tag + 16 padded = 32 bytes = 43 chars
        assert_eq!(lines[1], b"");
        assert_eq!(lines[2], b" \t \r");
        assert!(lines[3].starts_with(b"\t") && !lines[3].ends_with(b"\n"));
        assert_eq!(decrypt_lines(&DEK, 16, &body).unwrap(), plain);
    }

    #[test]
    fn lines_ws_off_encrypts_everything() {
        let plain = b"  a  \n\n \r\nx";
        let body = encrypt_lines(&DEK, false, 0, plain);
        let lines: Vec<&[u8]> = body.split(|&c| c == b'\n').collect();
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[0].len(), 28); // 16 + 5 bytes
        assert_eq!(lines[1].len(), 22); // the empty line is a bare tag
        assert!(lines[2].ends_with(b"\r") && lines[2].len() == 23 + 1);
        assert!(body.iter().all(|&c| c != b' '));
        assert_eq!(decrypt_lines(&DEK, 0, &body).unwrap(), plain);
    }

    #[test]
    fn lines_are_deterministic_and_independent() {
        let a = encrypt_lines(&DEK, true, 16, b"one\ntwo\nthree\n");
        let b = encrypt_lines(&DEK, true, 16, b"one\nTWO\nthree\none\n");
        let (a, b): (Vec<&[u8]>, Vec<&[u8]>) = (a.split(|&c| c == b'\n').collect(), b.split(|&c| c == b'\n').collect());
        assert_eq!(a[0], b[0]);
        assert_ne!(a[1], b[1]);
        assert_eq!(a[2], b[2]);
        assert_eq!(b[0], b[3]);
    }

    #[test]
    fn empty_input() {
        assert_eq!(encrypt_lines(&DEK, true, 16, b""), b"");
        assert_eq!(encrypt_lines(&DEK, false, 16, b""), b"");
        assert_eq!(decrypt_lines(&DEK, 16, b"").unwrap(), b"");
        let blob = encrypt_blob(&DEK, 8, b"");
        assert_eq!(blob.len(), 22 + 1);
        assert_eq!(decrypt_blob(&DEK, 8, &blob).unwrap(), b"");
        assert_eq!(decrypt_blob(&DEK, 8, b"").unwrap_err().kind, ErrorKind::Malformed);
        assert_eq!(
            decrypt_blob(&DEK, 8, b" \r\n\t").unwrap_err().kind,
            ErrorKind::Malformed
        );
    }

    #[test]
    fn lines_decrypt_errors() {
        let body = encrypt_lines(&DEK, true, 16, b"secret\n");
        assert_eq!(
            decrypt_lines(&DEK, 16, b"not base64!\n").unwrap_err().kind,
            ErrorKind::Malformed
        );
        assert_eq!(
            decrypt_lines(&DEK, 16, b"c2hvcnQ\n").unwrap_err().kind,
            ErrorKind::Malformed
        );
        let e = decrypt_lines(&DEK, 16, &[&body[..], b"AAAAA\n"].concat()).unwrap_err();
        assert_eq!(
            (e.kind, e.message.as_str()),
            (ErrorKind::Malformed, "line 2 is not a valid encrypted line")
        );
        let mut tampered = body.clone();
        tampered[5] = if tampered[5] == b'A' { b'B' } else { b'A' };
        assert_eq!(decrypt_lines(&DEK, 16, &tampered).unwrap_err().kind, ErrorKind::Auth);
        assert_eq!(decrypt_lines(&[8; 32], 16, &body).unwrap_err().kind, ErrorKind::Auth);
        // Authentic but written without padding while the header claims padding.
        let unpadded = encrypt_lines(&DEK, true, 0, b"secret\n");
        assert_eq!(
            decrypt_lines(&DEK, 16, &unpadded).unwrap_err().kind,
            ErrorKind::Malformed
        );
    }

    #[test]
    fn blob_chunking() {
        let data: Vec<u8> = (0..100u8).collect();
        for (len, records) in [
            (0usize, 1usize),
            (1, 1),
            (9, 1),
            (10, 1),
            (11, 2),
            (20, 2),
            (21, 3),
            (100, 10),
        ] {
            let body = encrypt_blob(&DEK, 10, &data[..len]);
            assert!(body.ends_with(b"\n"));
            assert!(body.split(|&c| c == b'\n').all(|l| l.len() <= 76));
            let raw_len = b64url_decode(&body.iter().copied().filter(|&c| c != b'\n').collect::<Vec<_>>())
                .unwrap()
                .len();
            assert_eq!(raw_len, len + records * 16, "len {len}");
            assert_eq!(decrypt_blob(&DEK, 10, &body).unwrap(), &data[..len]);
            // CRLF and stray blanks are ignored.
            let crlf = String::from_utf8(body.clone()).unwrap().replace('\n', " \t\r\n");
            assert_eq!(decrypt_blob(&DEK, 10, crlf.as_bytes()).unwrap(), &data[..len]);
        }
    }

    #[test]
    fn blob_detects_truncation_reordering_and_extension() {
        let data: Vec<u8> = (0..30u8).collect();
        let body = encrypt_blob(&DEK, 10, &data);
        let raw = b64url_decode(&body.iter().copied().filter(|&c| c != b'\n').collect::<Vec<_>>()).unwrap();
        let recs: Vec<&[u8]> = raw.chunks(26).collect();
        let enc = |parts: &[&[u8]]| b64url_encode(&parts.concat()).into_bytes();
        assert_eq!(decrypt_blob(&DEK, 10, &enc(&recs)).unwrap(), data);
        for bad in [
            enc(&recs[..2]),
            enc(&[recs[1], recs[0], recs[2]]),
            enc(&[recs[0], recs[1], recs[2], recs[2]]),
            enc(&[recs[0], recs[1], &recs[2][..20]]),
            enc(&[recs[2]]),
        ] {
            assert_eq!(decrypt_blob(&DEK, 10, &bad).unwrap_err().kind, ErrorKind::Auth);
        }
        assert_eq!(
            decrypt_blob(&DEK, 10, &enc(&[b"short"])).unwrap_err().kind,
            ErrorKind::Malformed
        );
        assert_eq!(decrypt_blob(&DEK, 10, b"***").unwrap_err().kind, ErrorKind::Malformed);
    }

    #[test]
    fn roundtrip_and_defaults() {
        let plain = b"a: 1\n  b: 2\n";
        let text = encrypt(plain, &[pw("x")], &cheap()).unwrap();
        assert!(text.starts_with("#ssenc1 lines ws=1 pad=16\n#slot pw argon2id m=64,t=1,p=1 "));
        assert_eq!(decrypt(text.as_bytes(), &pw("x")).unwrap(), plain);
        assert_eq!(decrypt(text.as_bytes(), &pw("y")).unwrap_err().kind, ErrorKind::Auth);
        // CRLF header lines are accepted.
        let crlf = text.replacen('\n', "\r\n", 2);
        assert_eq!(decrypt(crlf.as_bytes(), &pw("x")).unwrap(), plain);
        // Fresh encryptions differ (new data key), re-encryption with previous does not.
        assert_ne!(encrypt(plain, &[pw("x")], &cheap()).unwrap(), text);
        let again = EncryptOptions {
            previous: Some(text.clone().into_bytes()),
            ..Default::default()
        };
        assert_eq!(encrypt(plain, &[pw("x")], &again).unwrap(), text);
    }

    #[test]
    fn previous_supplies_layout_and_slots() {
        let first = EncryptOptions {
            preserve_whitespace: Some(false),
            pad: Some(0),
            seal: Some(true),
            ..cheap()
        };
        let text = encrypt(b"a\nb\n", &[pw("x"), pw("y")], &first).unwrap();
        assert_eq!(text.lines().filter(|l| l.starts_with("#slot pw ")).count(), 2);
        let prev = || Some(text.clone().into_bytes());
        // An invalid kdf is not even looked at: no slots are made.
        let next = encrypt(
            b"a\nc\n",
            &[pw("nope"), pw("y")],
            &EncryptOptions {
                previous: prev(),
                kdf: Some("bogus".into()),
                ..Default::default()
            },
        )
        .unwrap();
        let (old, new): (Vec<&str>, Vec<&str>) = (text.lines().collect(), next.lines().collect());
        assert_eq!(old[..3], new[..3]);
        assert_ne!(old[3], new[3]); // seal
        assert_eq!(old[4], new[4]);
        assert_ne!(old[5], new[5]);
        assert_eq!(
            inspect(next.as_bytes()).unwrap().to_json(),
            r#"{"format":"ssenc1","mode":"lines","ws":false,"pad":0,"seal":true,"slots":[{"type":"pw","kdf":"argon2id","m":64,"t":1,"p":1},{"type":"pw","kdf":"argon2id","m":64,"t":1,"p":1}]}"#
        );
        // Explicit options win; switching to blob drops the seal.
        let blob = encrypt(
            b"a\nc\n",
            &[pw("x")],
            &EncryptOptions {
                previous: prev(),
                mode: Some(Mode::Blob),
                chunk: Some(2),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            inspect(blob.as_bytes()).unwrap(),
            InspectResult::Blob {
                chunk: 2,
                slots: vec![SlotInfo::Pw { m: 64, t: 1, p: 1 }; 2]
            }
        );
        assert_eq!(decrypt(blob.as_bytes(), &pw("y")).unwrap(), b"a\nc\n");
        let e = encrypt(
            b"",
            &[pw("nope")],
            &EncryptOptions {
                previous: prev(),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(e.kind, ErrorKind::Auth);
        let e = encrypt(
            b"",
            &[pw("x")],
            &EncryptOptions {
                previous: Some(b"junk".to_vec()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(e.kind, ErrorKind::Malformed);
    }

    #[test]
    fn seal_detects_line_removal() {
        let text = encrypt(
            b"a\nb\nc\n",
            &[pw("x")],
            &EncryptOptions {
                seal: Some(true),
                ..cheap()
            },
        )
        .unwrap();
        let lines: Vec<&str> = text.split_inclusive('\n').collect();
        assert!(lines[2].starts_with("#seal "));
        let cut = [lines[0], lines[1], lines[2], lines[3], lines[5]].concat();
        assert_eq!(decrypt(cut.as_bytes(), &pw("x")).unwrap_err().kind, ErrorKind::Auth);
        let unsealed = [lines[0], lines[1], lines[3], lines[5]].concat();
        assert_eq!(decrypt(unsealed.as_bytes(), &pw("x")).unwrap(), b"a\nc\n");
    }

    #[test]
    fn usage_errors() {
        let kind = |keys: &[Key], opts: EncryptOptions| encrypt(b"x", keys, &opts).unwrap_err().kind;
        assert_eq!(kind(&[], cheap()), ErrorKind::Usage);
        assert_eq!(kind(&[pw("")], cheap()), ErrorKind::Usage);
        assert_eq!(
            kind(
                &[pw("x")],
                EncryptOptions {
                    pad: Some(4097),
                    ..cheap()
                }
            ),
            ErrorKind::Usage
        );
        assert_eq!(
            kind(
                &[pw("x")],
                EncryptOptions {
                    chunk: Some(0),
                    ..cheap()
                }
            ),
            ErrorKind::Usage
        );
        assert_eq!(
            kind(
                &[pw("x")],
                EncryptOptions {
                    chunk: Some(1_048_577),
                    ..cheap()
                }
            ),
            ErrorKind::Usage
        );
        assert_eq!(
            kind(
                &[pw("x")],
                EncryptOptions {
                    mode: Some(Mode::Blob),
                    seal: Some(true),
                    ..cheap()
                }
            ),
            ErrorKind::Usage
        );
        assert_eq!(
            kind(
                &[pw("x")],
                EncryptOptions {
                    kdf: Some("fast".into()),
                    ..Default::default()
                }
            ),
            ErrorKind::Usage
        );
        let no_source = Key::Ssh {
            public_key: None,
            fingerprint: None,
            agent_socket: None,
            signer: None,
        };
        assert_eq!(kind(&[no_source], cheap()), ErrorKind::Usage);
        let text = encrypt(b"x", &[pw("x")], &cheap()).unwrap();
        assert_eq!(decrypt(text.as_bytes(), &pw("")).unwrap_err().kind, ErrorKind::Usage);
        assert_eq!(
            rekey(text.as_bytes(), &pw("x"), &[], &RekeyOptions::default())
                .unwrap_err()
                .kind,
            ErrorKind::Usage
        );
        assert_eq!(decrypt(b"plain text", &pw("x")).unwrap_err().kind, ErrorKind::Malformed);
        assert_eq!(inspect(b"").unwrap_err().kind, ErrorKind::Malformed);
    }

    #[test]
    fn rekey_modes() {
        let opts = EncryptOptions {
            pad: Some(4),
            seal: Some(true),
            ..cheap()
        };
        let text = encrypt(b" a\nb\n", &[pw("old")], &opts).unwrap();
        let cheap_rekey = |rotate| RekeyOptions {
            rotate_data_key: rotate,
            kdf: Some("m=64,t=1,p=1".into()),
        };

        let rewrapped = rekey(
            text.as_bytes(),
            &pw("old"),
            &[pw("new"), pw("new2")],
            &cheap_rekey(false),
        )
        .unwrap();
        assert_eq!(body_of(&rewrapped), body_of(&text));
        assert_eq!(rewrapped.lines().next(), text.lines().next());
        assert_eq!(rewrapped.lines().nth(3), text.lines().nth(2)); // seal line kept
        assert_eq!(decrypt(rewrapped.as_bytes(), &pw("new2")).unwrap(), b" a\nb\n");
        assert_eq!(
            decrypt(rewrapped.as_bytes(), &pw("old")).unwrap_err().kind,
            ErrorKind::Auth
        );

        let rotated = rekey(text.as_bytes(), &pw("old"), &[pw("new")], &cheap_rekey(true)).unwrap();
        assert_ne!(body_of(&rotated), body_of(&text));
        assert_eq!(inspect(rotated.as_bytes()).unwrap(), inspect(text.as_bytes()).unwrap());
        assert_eq!(decrypt(rotated.as_bytes(), &pw("new")).unwrap(), b" a\nb\n");
        assert_eq!(
            rekey(text.as_bytes(), &pw("bad"), &[pw("new")], &cheap_rekey(true))
                .unwrap_err()
                .kind,
            ErrorKind::Auth
        );

        let blob = encrypt(
            &[1, 2, 3, 4, 5],
            &[pw("old")],
            &EncryptOptions {
                mode: Some(Mode::Blob),
                chunk: Some(2),
                ..cheap()
            },
        )
        .unwrap();
        let rotated = rekey(blob.as_bytes(), &pw("old"), &[pw("new")], &cheap_rekey(true)).unwrap();
        assert!(rotated.starts_with("#ssenc1 blob chunk=2\n"));
        assert_eq!(decrypt(rotated.as_bytes(), &pw("new")).unwrap(), [1, 2, 3, 4, 5]);
    }

    // A deterministic stand-in for ssh-agent, so the signer callback path needs no agent.
    fn fake_ssh_key(seed: u8) -> Key {
        let blob = [ssh_string(b"ssh-ed25519"), ssh_string(&[seed; 32])].concat();
        let signer: SshSigner = Arc::new(|blob: &[u8], data: &[u8]| {
            let sig = [hmac_sha256(blob, &[data]), hmac_sha256(blob, &[data, b"2"])].concat();
            Ok([ssh_string(b"ssh-ed25519"), ssh_string(&sig)].concat())
        });
        Key::Ssh {
            public_key: Some(format!("ssh-ed25519 {} fake", crate::util::b64std_encode_nopad(&blob))),
            fingerprint: None,
            agent_socket: None,
            signer: Some(signer),
        }
    }

    #[test]
    fn ssh_keys_through_signer_callback() {
        let (k1, k2, k3) = (fake_ssh_key(1), fake_ssh_key(2), fake_ssh_key(3));
        let text = encrypt(b"top secret\n", &[k1.clone(), pw("x"), k2.clone()], &cheap()).unwrap();
        let slots: Vec<&str> = text.lines().filter(|l| l.starts_with("#slot ")).collect();
        assert_eq!(slots.len(), 3);
        assert!(slots[0].starts_with("#slot pw ")); // password slots come first
        assert!(slots[1].starts_with("#slot ssh ssh-ed25519 SHA256:"));
        for k in [&k1, &k2, &pw("x")] {
            assert_eq!(decrypt(text.as_bytes(), k).unwrap(), b"top secret\n");
        }
        assert_eq!(decrypt(text.as_bytes(), &k3).unwrap_err().kind, ErrorKind::Auth);
        let again = EncryptOptions {
            previous: Some(text.clone().into_bytes()),
            ..Default::default()
        };
        assert_eq!(encrypt(b"top secret\n", &[k3, k2], &again).unwrap(), text);
        let InspectResult::Lines { slots, .. } = inspect(text.as_bytes()).unwrap() else {
            panic!()
        };
        assert!(matches!(&slots[2], SlotInfo::Ssh { key_type, .. } if key_type == "ssh-ed25519"));
    }

    #[test]
    fn unsupported_ssh_key_type_is_env() {
        let blob = [
            ssh_string(b"ecdsa-sha2-nistp256"),
            ssh_string(b"nistp256"),
            ssh_string(&[4; 65]),
        ]
        .concat();
        let key = Key::ssh_public_key(format!(
            "ecdsa-sha2-nistp256 {}",
            crate::util::b64std_encode_nopad(&blob)
        ));
        assert_eq!(
            encrypt(b"x", std::slice::from_ref(&key), &cheap()).unwrap_err().kind,
            ErrorKind::Env
        );
        let text = encrypt(b"x", &[pw("x")], &cheap()).unwrap();
        assert_eq!(decrypt(text.as_bytes(), &key).unwrap_err().kind, ErrorKind::Env);
        assert_eq!(
            decrypt(text.as_bytes(), &Key::ssh_public_key("garbage"))
                .unwrap_err()
                .kind,
            ErrorKind::Env
        );
    }
}
