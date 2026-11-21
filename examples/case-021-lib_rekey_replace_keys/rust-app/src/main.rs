// case-021: rekey replaces the keys of an encrypted text.
use ssenc::{decrypt, encrypt, inspect, rekey, EncryptOptions, ErrorKind, Kdf, Key, Mode, RekeyOptions};
use std::fs;

fn data_lines(text: &str) -> Vec<&str> {
    text.lines().filter(|line| !line.is_empty() && !line.starts_with('#')).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let old_key = Key::password(fs::read_to_string("tmp/old-password.txt")?.trim());
    let new_key = Key::password(fs::read_to_string("tmp/new-password.txt")?.trim());
    let kdf: Kdf = "m=19456,t=2,p=1".into(); // lower cost, only to keep the demo quick
    let plain = "host: db.internal\nuser: admin\npassword: hunter2\n";

    let original = encrypt(plain.as_bytes(), &[old_key.clone()], &EncryptOptions { kdf: Some(kdf.clone()), ..Default::default() })?;
    println!("encrypted with the old password:\n{original}");

    // --- rekey(text, old key, new keys, options): everything is encrypted again under a
    //     new data key (rotate_data_key is true by default) -----------------------------
    let rotate = RekeyOptions { kdf: Some(kdf.clone()), ..Default::default() };
    let rotated = rekey(original.as_bytes(), &old_key, &[new_key.clone()], &rotate)?;
    println!("after rekey:\n{rotated}");
    assert_eq!(decrypt(rotated.as_bytes(), &old_key).unwrap_err().kind, ErrorKind::Auth);
    assert_eq!(decrypt(rotated.as_bytes(), &new_key)?, plain.as_bytes());
    assert!(data_lines(&rotated).iter().all(|line| !data_lines(&original).contains(line)));
    println!("the old password is rejected, the new one opens it, and every line changed: ok\n");

    // --- rotate_data_key: false -> only the key line is replaced, the data lines stay ----
    // Cheap and a small diff, but weaker: whoever knows the old password and kept an old
    // copy can still read later versions.
    let rewrap = RekeyOptions { rotate_data_key: false, kdf: Some(kdf.clone()) };
    let rewrapped = rekey(original.as_bytes(), &old_key, &[new_key.clone()], &rewrap)?;
    assert_eq!(data_lines(&rewrapped), data_lines(&original));
    assert_eq!(decrypt(rewrapped.as_bytes(), &old_key).unwrap_err().kind, ErrorKind::Auth);
    assert_eq!(decrypt(rewrapped.as_bytes(), &new_key)?, plain.as_bytes());
    println!("rotate_data_key: false -> data lines identical, only the key line differs: ok");

    // --- several new keys: any one of them opens the result -----------------------------
    let third_key = Key::password("a third password");
    let two = rekey(original.as_bytes(), &old_key, &[new_key.clone(), third_key.clone()], &rotate)?;
    println!("\ntwo new keys: {}", inspect(two.as_bytes())?.to_json());
    assert_eq!(decrypt(two.as_bytes(), &new_key)?, plain.as_bytes());
    assert_eq!(decrypt(two.as_bytes(), &third_key)?, plain.as_bytes());

    // --- kdf: the cost of the new password keys (the default cost when left out) --------
    let default_cost = rekey(two.as_bytes(), &third_key, &[new_key.clone()], &RekeyOptions::default())?;
    println!("rekey without kdf uses the default cost: {}", inspect(default_cost.as_bytes())?.to_json());

    // --- the mode and its settings are kept ----------------------------------------------
    let blob_options = EncryptOptions { mode: Some(Mode::Blob), chunk: Some(1024), kdf: Some(kdf.clone()), ..Default::default() };
    let blob = encrypt(&[0, 1, 2, 255], &[old_key.clone()], &blob_options)?;
    let blob_rekeyed = rekey(blob.as_bytes(), &old_key, &[new_key.clone()], &rotate)?;
    println!("\na blob stays a blob with its chunk size: {}", inspect(blob_rekeyed.as_bytes())?.to_json());
    assert_eq!(decrypt(blob_rekeyed.as_bytes(), &new_key)?, [0, 1, 2, 255]);
    Ok(())
}
