//! Minimal ssh-agent client: list identities (11) and sign (13).

use crate::ssh::{ssh_fingerprint, ssh_key_type};
use crate::util::{ssh_read_string, ssh_string, Error};
use std::io::{Read, Write};

const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
const SSH_AGENT_RSA_SHA2_512: u32 = 4;
const MAX_REPLY: usize = 1_048_576;

fn agent_socket_path(explicit: Option<&str>) -> Result<String, Error> {
    if let Some(p) = explicit.filter(|p| !p.is_empty()) {
        return Ok(p.to_string());
    }
    if let Some(p) = std::env::var_os("SSH_AUTH_SOCK").filter(|p| !p.is_empty()) {
        return Ok(p.to_string_lossy().into_owned());
    }
    if cfg!(windows) {
        return Ok(r"\\.\pipe\openssh-ssh-agent".to_string());
    }
    Err(Error::env("ssh-agent not available: SSH_AUTH_SOCK is not set"))
}

#[cfg(unix)]
fn connect(path: &str) -> std::io::Result<impl Read + Write> {
    std::os::unix::net::UnixStream::connect(path)
}

// The OpenSSH agent of Windows listens on a named pipe, which opens like a file.
#[cfg(windows)]
fn connect(path: &str) -> std::io::Result<impl Read + Write> {
    std::fs::OpenOptions::new().read(true).write(true).open(path)
}

#[cfg(not(any(unix, windows)))]
fn connect(_path: &str) -> std::io::Result<std::fs::File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "no ssh-agent transport on this platform",
    ))
}

fn exchange(stream: &mut (impl Read + Write), body: &[u8]) -> Result<Vec<u8>, String> {
    let closed = |e: std::io::Error| match e.kind() {
        std::io::ErrorKind::UnexpectedEof => "connection closed before a full reply".to_string(),
        _ => e.to_string(),
    };
    let mut msg = (body.len() as u32).to_be_bytes().to_vec();
    msg.extend_from_slice(body);
    stream.write_all(&msg).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).map_err(closed)?;
    let len = u32::from_be_bytes(head) as usize;
    if len > MAX_REPLY {
        return Err("oversized reply".to_string());
    }
    let mut reply = vec![0u8; len];
    stream.read_exact(&mut reply).map_err(closed)?;
    Ok(reply)
}

fn agent_request(socket: Option<&str>, body: &[u8]) -> Result<Vec<u8>, Error> {
    let path = agent_socket_path(socket)?;
    let fail = |why: String| Error::env(format!("ssh-agent at {path}: {why}"));
    let mut stream = connect(&path).map_err(|e| fail(e.to_string()))?;
    exchange(&mut stream, body).map_err(fail)
}

fn read_string(b: &[u8], off: usize) -> Result<(&[u8], usize), Error> {
    ssh_read_string(b, off).ok_or_else(|| Error::env("ssh-agent sent a truncated reply"))
}

fn parse_identities(reply: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    if reply.first() != Some(&SSH_AGENT_IDENTITIES_ANSWER) || reply.len() < 5 {
        return Err(Error::env("ssh-agent refused to list keys"));
    }
    let count = u32::from_be_bytes([reply[1], reply[2], reply[3], reply[4]]);
    let mut keys = Vec::new();
    let mut off = 5;
    for _ in 0..count {
        let (blob, next) = read_string(reply, off)?;
        let (_comment, next) = read_string(reply, next)?;
        keys.push(blob.to_vec());
        off = next;
    }
    Ok(keys)
}

pub(crate) fn agent_list_keys(socket: Option<&str>) -> Result<Vec<Vec<u8>>, Error> {
    parse_identities(&agent_request(socket, &[SSH_AGENTC_REQUEST_IDENTITIES])?)
}

fn sign_request(blob: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    let flags = if ssh_key_type(blob)? == "ssh-rsa" {
        SSH_AGENT_RSA_SHA2_512
    } else {
        0
    };
    let mut req = vec![SSH_AGENTC_SIGN_REQUEST];
    req.extend_from_slice(&ssh_string(blob));
    req.extend_from_slice(&ssh_string(data));
    req.extend_from_slice(&flags.to_be_bytes());
    Ok(req)
}

pub(crate) fn agent_sign(socket: Option<&str>, blob: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    let reply = agent_request(socket, &sign_request(blob, data)?)?;
    if reply.first() != Some(&SSH_AGENT_SIGN_RESPONSE) {
        return Err(Error::env(format!(
            "ssh-agent could not sign with key {} (is it loaded? check: ssh-add -l)",
            ssh_fingerprint(blob)
        )));
    }
    Ok(read_string(&reply, 1)?.0.to_vec())
}

pub(crate) fn agent_find_key(socket: Option<&str>, fingerprint: &str) -> Result<Vec<u8>, Error> {
    for blob in agent_list_keys(socket)? {
        if ssh_fingerprint(&blob) == fingerprint {
            return Ok(blob);
        }
    }
    Err(Error::env(format!(
        "key {fingerprint} is not loaded in ssh-agent (check: ssh-add -l)"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::ErrorKind;

    struct Fake {
        reply: std::io::Cursor<Vec<u8>>,
        sent: Vec<u8>,
    }
    impl Read for Fake {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.reply.read(buf)
        }
    }
    impl Write for Fake {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.sent.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    fn fake(reply: &[u8]) -> Fake {
        Fake {
            reply: std::io::Cursor::new(reply.to_vec()),
            sent: Vec::new(),
        }
    }

    #[test]
    fn frames_requests_and_replies() {
        let mut f = fake(&[0, 0, 0, 2, 12, 9, 99]);
        assert_eq!(exchange(&mut f, &[11]).unwrap(), [12, 9]);
        assert_eq!(f.sent, [0, 0, 0, 1, 11]);
        assert_eq!(
            exchange(&mut fake(&[0, 0, 0, 5, 1]), &[11]).unwrap_err(),
            "connection closed before a full reply"
        );
        assert_eq!(
            exchange(&mut fake(&[0, 0x10, 0, 1]), &[11]).unwrap_err(),
            "oversized reply"
        );
        assert_eq!(
            exchange(&mut fake(&[]), &[11]).unwrap_err(),
            "connection closed before a full reply"
        );
    }

    #[test]
    fn parses_identity_lists() {
        let mut reply = vec![12, 0, 0, 0, 2];
        for (k, c) in [(&b"key-one"[..], &b"a"[..]), (b"key-two", b"")] {
            reply.extend_from_slice(&ssh_string(k));
            reply.extend_from_slice(&ssh_string(c));
        }
        assert_eq!(
            parse_identities(&reply).unwrap(),
            vec![b"key-one".to_vec(), b"key-two".to_vec()]
        );
        assert_eq!(
            parse_identities(&reply[..reply.len() - 1]).unwrap_err().kind,
            ErrorKind::Env
        );
        assert_eq!(parse_identities(&[5]).unwrap_err().kind, ErrorKind::Env);
        assert_eq!(parse_identities(&[]).unwrap_err().kind, ErrorKind::Env);
    }

    #[test]
    fn sign_request_uses_sha512_flag_only_for_rsa() {
        let rsa = ssh_string(b"ssh-rsa");
        let ed = ssh_string(b"ssh-ed25519");
        assert_eq!(sign_request(&rsa, b"x").unwrap().last(), Some(&4));
        let req = sign_request(&ed, b"x").unwrap();
        assert_eq!(req[0], 13);
        assert_eq!(&req[req.len() - 4..], [0, 0, 0, 0]);
    }

    #[cfg(unix)]
    #[test]
    fn unreachable_agent_is_env() {
        let e = agent_list_keys(Some("/nonexistent/ssenc-agent")).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Env);
        assert!(e.message.starts_with("ssh-agent at /nonexistent/ssenc-agent: "));
    }
}
