//! ssh key handling (SPEC.md section 2.3).

use crate::prim::{hkdf32, sha256, sha512};
use crate::util::{b64std_decode, b64std_encode_nopad, latin1, ssh_read_string, ssh_string, Error};
use std::sync::Arc;

/// Produces the signature blob for `data` with the key `public_key_blob`.
///
/// Must return `string(algorithm) || string(signature)` exactly as an ssh-agent does; for
/// an ssh-rsa key the algorithm must be `rsa-sha2-512`.
pub type SshSigner = Arc<dyn Fn(&[u8], &[u8]) -> Result<Vec<u8>, Error> + Send + Sync>;

pub const SSH_NAMESPACE: &str = "ssenc-v1@stopsopa";

/// The key type named inside a public key blob, e.g. `ssh-ed25519`.
pub fn ssh_key_type(blob: &[u8]) -> Result<String, Error> {
    match ssh_read_string(blob, 0) {
        Some((s, _)) => Ok(latin1(s)),
        None => Err(Error::env("invalid ssh public key")),
    }
}

pub(crate) fn ssh_require_supported(key_type: &str) -> Result<(), Error> {
    if key_type != "ssh-ed25519" && key_type != "ssh-rsa" {
        return Err(Error::env(format!(
            "unsupported ssh key type '{key_type}': only ssh-ed25519 and ssh-rsa give deterministic signatures"
        )));
    }
    Ok(())
}

// What JavaScript's trim() and \s treat as white space beyond Rust's definition.
fn is_space(c: char) -> bool {
    c.is_whitespace() || c == '\u{feff}'
}

/// Parses the content of an OpenSSH public key file (`type base64 [comment]`) to the key blob.
pub fn ssh_parse_public_key(text: &str) -> Result<Vec<u8>, Error> {
    for line in text.split('\n') {
        let mut parts = line.split(is_space).filter(|p| !p.is_empty());
        let (Some(kind), Some(b64)) = (parts.next(), parts.next()) else {
            continue;
        };
        if !(kind.starts_with("ssh-") || kind.starts_with("ecdsa-") || kind.starts_with("sk-")) {
            continue;
        }
        if let Some(blob) = b64std_decode(b64) {
            if ssh_key_type(&blob)? == kind {
                return Ok(blob);
            }
        }
    }
    Err(Error::env("not an OpenSSH public key"))
}

/// `SHA256:...` as printed by `ssh-keygen -l`.
pub fn ssh_fingerprint(blob: &[u8]) -> String {
    format!("SHA256:{}", b64std_encode_nopad(&sha256(blob)))
}

pub(crate) fn ssh_signed_data(salt: &[u8]) -> Vec<u8> {
    let mut message = b"ssenc1 ssh slot".to_vec();
    message.extend_from_slice(salt);
    let mut out = b"SSHSIG".to_vec();
    out.extend_from_slice(&ssh_string(SSH_NAMESPACE.as_bytes()));
    out.extend_from_slice(&ssh_string(b""));
    out.extend_from_slice(&ssh_string(b"sha512"));
    out.extend_from_slice(&ssh_string(&sha512(&message)));
    out
}

pub(crate) fn ssh_kek(blob: &[u8], salt: &[u8], signer: &SshSigner) -> Result<[u8; 32], Error> {
    let key_type = ssh_key_type(blob)?;
    ssh_require_supported(&key_type)?;
    let sig = zeroize::Zeroizing::new(signer(blob, &ssh_signed_data(salt))?);
    let expected = if key_type == "ssh-rsa" {
        "rsa-sha2-512"
    } else {
        "ssh-ed25519"
    };
    let ok = ssh_read_string(&sig, 0)
        .and_then(|(alg, next)| ssh_read_string(&sig, next).map(|(_, end)| (alg, end)))
        .is_some_and(|(alg, end)| end == sig.len() && alg == expected.as_bytes());
    if !ok {
        return Err(Error::env(format!(
            "ssh signer returned an unexpected signature (need {expected})"
        )));
    }
    Ok(hkdf32(&sig, Some(salt), b"ssenc1/ssh-kek"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::ErrorKind;

    fn ed() -> String {
        let blob = [ssh_string(b"ssh-ed25519"), ssh_string(&[9; 32])].concat();
        format!("ssh-ed25519 {} test@host", b64std_encode_nopad(&blob))
    }

    #[test]
    fn parses_public_key_lines() {
        let blob = ssh_parse_public_key(&ed()).unwrap();
        assert_eq!(blob.len(), 51);
        assert_eq!(ssh_key_type(&blob).unwrap(), "ssh-ed25519");
        let with_noise = format!("\u{feff}# comment\r\n\r\n  {}==  \r\n", ed().replace(" test@host", ""));
        assert_eq!(ssh_parse_public_key(&with_noise).unwrap(), blob);
        assert!(ssh_fingerprint(&blob).starts_with("SHA256:"));
        assert_eq!(ssh_fingerprint(&blob).len(), 7 + 43);
    }

    #[test]
    fn rejects_non_keys() {
        for bad in [
            "",
            "hello world",
            "ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIAAA",
            "ssh-ed25519 !!!!",
        ] {
            assert_eq!(ssh_parse_public_key(bad).unwrap_err().kind, ErrorKind::Env, "{bad}");
        }
    }

    #[test]
    fn rejects_unsupported_types_and_bad_signatures() {
        assert_eq!(
            ssh_require_supported("ecdsa-sha2-nistp256").unwrap_err().kind,
            ErrorKind::Env
        );
        let blob = ssh_parse_public_key(&ed()).unwrap();
        let good: SshSigner = Arc::new(|_, _| Ok([ssh_string(b"ssh-ed25519"), ssh_string(&[7; 64])].concat()));
        assert!(ssh_kek(&blob, &[0; 32], &good).is_ok());
        let wrong_alg: SshSigner = Arc::new(|_, _| Ok([ssh_string(b"rsa-sha2-512"), ssh_string(&[7; 64])].concat()));
        assert_eq!(ssh_kek(&blob, &[0; 32], &wrong_alg).unwrap_err().kind, ErrorKind::Env);
        let trailing: SshSigner =
            Arc::new(|_, _| Ok([ssh_string(b"ssh-ed25519"), ssh_string(&[7; 64]), vec![0]].concat()));
        assert_eq!(ssh_kek(&blob, &[0; 32], &trailing).unwrap_err().kind, ErrorKind::Env);
    }

    #[test]
    fn signed_data_layout() {
        let d = ssh_signed_data(&[1; 32]);
        assert!(d.starts_with(b"SSHSIG\0\0\0\x11ssenc-v1@stopsopa\0\0\0\0\0\0\0\x06sha512\0\0\0\x40"));
        assert_eq!(d.len(), 6 + 4 + 17 + 4 + 4 + 6 + 4 + 64);
    }
}
