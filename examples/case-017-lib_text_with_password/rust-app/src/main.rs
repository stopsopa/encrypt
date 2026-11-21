// case-017: encrypt and decrypt a text with a password, from Rust.
// Run it with ../rust.sh, which creates tmp/password.txt first.
use ssenc::{decrypt, encrypt, EncryptOptions, Key};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("library version {}", ssenc::VERSION);

    // The password is the demo password made by prepare.sh.
    let password = std::fs::read_to_string("tmp/password.txt")?;
    let key = Key::password(password.trim());

    // encrypt: bytes go in, an ASCII String comes out. The second argument is a list of
    // keys (one here); the third the options (all defaults here).
    let plain = "user: admin\npassword: hunter2\n";
    let encrypted: String = encrypt(plain.as_bytes(), &[key.clone()], &EncryptOptions::default())?;
    println!("\nencrypted:\n{encrypted}");

    // decrypt: back to the original bytes.
    let bytes: Vec<u8> = decrypt(encrypted.as_bytes(), &key)?;
    println!("decrypted: {} bytes, first five: {:?}", bytes.len(), &bytes[..5]);
    let text = String::from_utf8(bytes)?;
    println!("decrypted as a string:\n{text}");
    assert_eq!(text, plain);

    // Encrypting the same text again gives different output: every call makes a new random
    // data key. (How to keep unchanged lines identical is shown in case-019.)
    let again = encrypt(plain.as_bytes(), &[key.clone()], &EncryptOptions::default())?;
    assert_ne!(again, encrypted);
    println!("encrypting the same text again gives a different result: ok");

    // The password may also be given as bytes.
    let key_from_bytes = Key::password(password.trim().as_bytes().to_vec());
    assert_eq!(decrypt(again.as_bytes(), &key_from_bytes)?, plain.as_bytes());
    println!("a password given as bytes opens it as well: ok");
    Ok(())
}
