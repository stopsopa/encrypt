// case-023: an ssh key WITHOUT ssh-agent. The library never needs the private key: it needs
// one signature. `signer` is the function that produces it, so the key can live anywhere:
// a file (as here), a vault, an HSM, a cloud key service.
//
// To stay free of extra crates this demo lets the `openssl` command make the signature;
// a real program would call its signing library or service at that place.
use ssenc::{decrypt, encrypt, inspect, EncryptOptions, Error, ErrorKind, Key, SshSigner};
use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// SSH wire format of a byte string: 4-byte big-endian length, then the bytes.
fn ssh_string(bytes: &[u8]) -> Vec<u8> {
    let mut out = (bytes.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}

/// Ed25519 signature of `data` with the private key in `pem_file`, made by openssl.
fn ed25519_sign(pem_file: &str, data: &[u8]) -> Result<Vec<u8>, Error> {
    let env_error = |message: String| Error { kind: ErrorKind::Env, message };
    fs::write("tmp/to-sign.bin", data).map_err(|e| env_error(format!("cannot write tmp/to-sign.bin: {e}")))?;
    let output = Command::new("openssl")
        .args(["pkeyutl", "-sign", "-inkey", pem_file, "-rawin", "-in", "tmp/to-sign.bin"])
        .output()
        .map_err(|e| env_error(format!("cannot run openssl: {e}")))?;
    if !output.status.success() || output.stdout.len() != 64 {
        return Err(env_error(format!("openssl could not sign: {}", String::from_utf8_lossy(&output.stderr).trim())));
    }
    Ok(output.stdout)
}

/// A signer gets the public key blob and the data to sign, and returns what an ssh-agent
/// would return: string(algorithm) followed by string(signature).
fn signer_for(pem_file: &'static str, calls: Arc<AtomicUsize>) -> SshSigner {
    Arc::new(move |public_key_blob: &[u8], data: &[u8]| {
        calls.fetch_add(1, Ordering::SeqCst);
        println!("    signer called: sign {} bytes for a key blob of {} bytes", data.len(), public_key_blob.len());
        let signature = ed25519_sign(pem_file, data)?; // Ed25519: always the same signature for the same data
        Ok([ssh_string(b"ssh-ed25519"), ssh_string(&signature)].concat())
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // No agent is running: rust.sh did not start one.
    assert!(std::env::var("SSH_AUTH_SOCK").is_err());
    let public_key = fs::read_to_string("tmp/signer_key.pub")?;
    let calls = Arc::new(AtomicUsize::new(0));

    // With a signer, public_key is required (the fingerprint alone is not enough).
    let key = Key::Ssh {
        public_key: Some(public_key.clone()),
        fingerprint: None,
        agent_socket: None,
        signer: Some(signer_for("tmp/signer_key.pem", calls.clone())),
    };

    let plain = "API_KEY=8f2c1d\nDB_PASSWORD=hunter2\n";
    println!("encrypt:");
    let encrypted = encrypt(plain.as_bytes(), &[key.clone()], &EncryptOptions::default())?;
    println!("{encrypted}");
    println!("the key slot looks exactly like one made through ssh-agent: {}", inspect(encrypted.as_bytes())?.to_json());

    println!("\ndecrypt:");
    assert_eq!(decrypt(encrypted.as_bytes(), &key)?, plain.as_bytes());
    println!("decrypted correctly; the signer was called {} times (once per operation)", calls.load(Ordering::SeqCst));

    // A signer for another private key cannot open it.
    let wrong = Key::Ssh {
        public_key: Some(public_key.clone()),
        fingerprint: None,
        agent_socket: None,
        signer: Some(signer_for("tmp/other_key.pem", Arc::new(AtomicUsize::new(0)))),
    };
    assert_eq!(decrypt(encrypted.as_bytes(), &wrong).unwrap_err().kind, ErrorKind::Auth);
    println!("a signer that uses a different private key is rejected (AUTH): ok");

    // A signer that fails: its error is what the caller gets.
    let broken: SshSigner = Arc::new(|_blob: &[u8], _data: &[u8]| Err(Error { kind: ErrorKind::Env, message: "the vault is sealed".to_string() }));
    let failing = Key::Ssh { public_key: Some(public_key), fingerprint: None, agent_socket: None, signer: Some(broken) };
    let error = decrypt(encrypted.as_bytes(), &failing).unwrap_err();
    assert_eq!(error.kind, ErrorKind::Env);
    println!("a signer that fails is reported: {error}");
    Ok(())
}
