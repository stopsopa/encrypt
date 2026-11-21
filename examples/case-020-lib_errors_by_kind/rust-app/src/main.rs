// case-020: every failure is an ssenc::Error with a `kind`. This demo provokes each kind.
use ssenc::{decrypt, encrypt, inspect, EncryptOptions, Error, ErrorKind, Key};
use std::fs;

/// Reports a failure and returns its kind.
fn failure<T>(what: &str, result: Result<T, Error>) -> ErrorKind {
    match result {
        Ok(_) => panic!("{what}: did not fail"),
        Err(error) => {
            // Display gives "KIND: message"; the fields are public too.
            println!("{what}\n    -> {error}   (kind {:?}, exit code {})", error.kind, error.kind.exit_code());
            error.kind
        }
    }
}

/// How it looks in real code: decide by kind, pass everything else on.
fn open(text: &str, password: &str) -> Result<Option<String>, Error> {
    match decrypt(text.as_bytes(), &Key::password(password)) {
        Ok(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).into_owned())),
        Err(error) if error.kind == ErrorKind::Auth => Ok(None), // ask again
        Err(error) => Err(error),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let password = fs::read_to_string("tmp/password.txt")?;
    let key = Key::password(password.trim());
    // lower cost, only to keep the demo quick
    let options = EncryptOptions { kdf: Some("m=19456,t=2,p=1".into()), ..Default::default() };
    let encrypted = encrypt(b"the secret\n", &[key.clone()], &options)?;

    // Auth: the key does not open the text, or the text was changed.
    assert_eq!(failure("wrong password", decrypt(encrypted.as_bytes(), &Key::password("wrong"))), ErrorKind::Auth);
    let mut lines: Vec<String> = encrypted.lines().map(String::from).collect();
    let first = if lines[2].starts_with('A') { "B" } else { "A" };
    lines[2].replace_range(0..1, first);
    assert_eq!(failure("one character of the encrypted text changed", decrypt(lines.join("\n").as_bytes(), &key)), ErrorKind::Auth);

    // Malformed: the input is not encrypted text of this format.
    assert_eq!(failure("decrypt of plain text", decrypt(b"just some text\n", &key)), ErrorKind::Malformed);
    assert_eq!(failure("inspect of plain text", inspect(b"just some text\n")), ErrorKind::Malformed);

    // Usage: the call itself is wrong.
    assert_eq!(failure("empty password", encrypt(b"x", &[Key::password("")], &options)), ErrorKind::Usage);
    assert_eq!(failure("pad out of range", encrypt(b"x", &[key.clone()], &EncryptOptions { pad: Some(100000), ..Default::default() })), ErrorKind::Usage);
    assert_eq!(failure("no key at all", encrypt(b"x", &[], &options)), ErrorKind::Usage);

    // Env: something outside the program is missing; here an ssh key without a reachable agent.
    let ssh_key = Key::ssh_public_key(fs::read_to_string("tmp/demo_ed25519.pub")?);
    assert_eq!(failure("ssh key, but no ssh-agent", encrypt(b"x", &[ssh_key], &options)), ErrorKind::Env);

    assert_eq!(open(&encrypted, "a guess")?, None);
    assert_eq!(open(&encrypted, password.trim())?, Some("the secret\n".to_string()));
    println!("\nopen() returned None for a wrong password and the text for the right one: ok");
    Ok(())
}
