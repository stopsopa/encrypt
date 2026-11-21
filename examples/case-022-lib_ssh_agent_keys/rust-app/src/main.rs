// case-022: ssh keys held by ssh-agent as encryption keys. rust.sh starts a private agent
// with the demo keys and sets SSH_AUTH_SOCK before it runs this program.
use ssenc::{decrypt, encrypt, inspect, rekey, ssh_fingerprint, ssh_key_type, ssh_parse_public_key};
use ssenc::{EncryptOptions, ErrorKind, InspectResult, Key, RekeyOptions};
use std::fs;

fn slot_count(text: &str) -> Result<usize, ssenc::Error> {
    Ok(match inspect(text.as_bytes())? {
        InspectResult::Lines { slots, .. } | InspectResult::Blob { slots, .. } => slots.len(),
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let plain = "API_KEY=8f2c1d\nDB_PASSWORD=hunter2\n";
    let defaults = EncryptOptions::default();

    // --- an ssh key is named by the content of its PUBLIC key file ----------------------
    // The private key stays in the agent: the library asks the agent for a signature and
    // derives the encryption key from it.
    let ed25519_pub = fs::read_to_string("tmp/demo_ed25519.pub")?;
    let ssh_key = Key::ssh_public_key(ed25519_pub.clone());
    let encrypted = encrypt(plain.as_bytes(), &[ssh_key.clone()], &defaults)?;
    println!("encrypted for the Ed25519 key:\n{encrypted}");
    assert_eq!(decrypt(encrypted.as_bytes(), &ssh_key)?, plain.as_bytes());
    println!("decrypted with the same key: ok");

    // --- helpers: key blob, key type, fingerprint (as printed by ssh-add -l) ------------
    let blob = ssh_parse_public_key(&ed25519_pub)?;
    let fingerprint = ssh_fingerprint(&blob);
    println!("\nkey type {}, fingerprint {fingerprint}", ssh_key_type(&blob)?);

    // --- the key can be named by fingerprint alone; it is then looked up in the agent ---
    assert_eq!(decrypt(encrypted.as_bytes(), &Key::ssh_fingerprint(fingerprint.clone()))?, plain.as_bytes());
    println!("decrypted with the key named by fingerprint: ok");

    // --- agent_socket: use a specific agent instead of $SSH_AUTH_SOCK -------------------
    let socket = std::env::var("SSH_AUTH_SOCK")?;
    let through_socket = Key::Ssh { public_key: Some(ed25519_pub.clone()), fingerprint: None, agent_socket: Some(socket.clone()), signer: None };
    assert_eq!(decrypt(encrypted.as_bytes(), &through_socket)?, plain.as_bytes());
    println!("decrypted through an explicitly named agent socket ({socket}): ok");

    // --- several keys: two ssh keys and a backup password; any one opens the text -------
    let rsa_key = Key::ssh_public_key(fs::read_to_string("tmp/demo_rsa.pub")?);
    let backup = Key::password(fs::read_to_string("tmp/backup-password.txt")?.trim());
    let all = [ssh_key.clone(), rsa_key.clone(), backup.clone()];
    let shared = encrypt(plain.as_bytes(), &all, &defaults)?;
    println!("\nthree key slots: {}", inspect(shared.as_bytes())?.to_json());
    for key in &all {
        assert_eq!(decrypt(shared.as_bytes(), key)?, plain.as_bytes());
    }
    println!("each of the three keys opens it: ok");

    // --- stable updates work with an ssh key as with a password -------------------------
    let longer = format!("{plain}REGION=eu-west-1\n");
    let update = EncryptOptions { previous: Some(shared.clone().into_bytes()), ..Default::default() };
    let updated = encrypt(longer.as_bytes(), &[rsa_key.clone()], &update)?;
    assert_eq!(updated.lines().filter(|line| !shared.lines().any(|old| old == *line)).count(), 1);
    assert_eq!(slot_count(&updated)?, 3);
    println!("update made with one key: one new line, all three key slots kept: ok");

    // --- rekey from a password to an ssh key ----------------------------------------------
    let only_ssh = rekey(shared.as_bytes(), &backup, &[ssh_key.clone()], &RekeyOptions::default())?;
    println!("after rekey to the ssh key only: {}", inspect(only_ssh.as_bytes())?.to_json());
    assert_eq!(decrypt(only_ssh.as_bytes(), &backup).unwrap_err().kind, ErrorKind::Auth);

    // --- what does not work ---------------------------------------------------------------
    // A key that is not loaded in the agent: Env.
    let absent = Key::ssh_fingerprint("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    assert_eq!(decrypt(encrypted.as_bytes(), &absent).unwrap_err().kind, ErrorKind::Env);
    println!("\na key that is not in the agent is rejected (ENV): ok");
    Ok(())
}
