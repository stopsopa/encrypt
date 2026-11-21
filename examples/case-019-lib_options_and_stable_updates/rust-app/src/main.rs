// case-019: every option of encrypt, and how to update an encrypted text so that only the
// edited lines change.
use ssenc::{decrypt, encrypt, inspect, EncryptOptions, ErrorKind, InspectResult, Kdf, KdfParams, Key};
use std::fs;

/// The encrypted lines without the header lines.
fn body(encrypted: &str) -> String {
    encrypted.lines().filter(|line| !line.starts_with('#')).collect::<Vec<_>>().join("\n")
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = Key::password(fs::read_to_string("tmp/password.txt")?.trim());
    let keys = [key.clone()];
    let plain = fs::read_to_string("tmp/app.yml")?;

    // --- kdf: the cost of turning the password into a key -----------------------------
    // KdfParams::DEFAULT (64 MiB, 3 passes), KdfParams::STRONG (1 GiB, 4 passes), explicit
    // numbers, or a string. The lower cost below is used for the rest of this demo only to
    // keep it quick.
    let kdf: Kdf = KdfParams { m: 19456, t: 2, p: 1 }.into(); // m is in KiB
    let same_kdf_from_text: Kdf = "m=19456,t=2,p=1".into();
    let fast = EncryptOptions { kdf: Some(kdf.clone()), ..Default::default() };

    let v1 = encrypt(plain.as_bytes(), &keys, &fast)?;
    println!("default options (indentation readable, lines padded to 16 bytes):\n{v1}");
    println!("{}", inspect(v1.as_bytes())?.to_json());

    // --- preserve_whitespace: false -> indentation and empty lines are encrypted too ----
    let no_ws = encrypt(plain.as_bytes(), &keys, &EncryptOptions { kdf: Some(same_kdf_from_text), preserve_whitespace: Some(false), ..Default::default() })?;
    println!("\npreserve_whitespace: false\n{}", body(&no_ws));

    // --- pad: 0 -> no padding; a bigger value hides line lengths better -----------------
    let pad0 = encrypt(plain.as_bytes(), &keys, &EncryptOptions { pad: Some(0), ..fast.clone() })?;
    let pad64 = encrypt(plain.as_bytes(), &keys, &EncryptOptions { pad: Some(64), ..fast.clone() })?;
    println!("pad: 0\n{}", body(&pad0));
    println!("pad: 64\n{}", body(&pad64));

    // --- previous: update an encrypted text; unchanged lines stay identical -------------
    let edited = plain.replace("port: 8080", "port: 9090");
    let update = EncryptOptions { previous: Some(v1.clone().into_bytes()), ..Default::default() };
    let v2 = encrypt(edited.as_bytes(), &keys, &update)?;
    let changed = v1.lines().zip(v2.lines()).filter(|(a, b)| a != b).count();
    println!("previous: {changed} of {} lines changed after editing one line", v2.lines().count());
    assert_eq!(changed, 1);
    assert_eq!(decrypt(v2.as_bytes(), &key)?, edited.as_bytes());

    // Without `previous` a new data key is made and every line changes.
    let unrelated = encrypt(edited.as_bytes(), &keys, &fast)?;
    let changed = v1.lines().zip(unrelated.lines()).filter(|(a, b)| a != b).count();
    assert_eq!(changed, 6); // the key line and all five non-empty lines
    println!("without previous: every line changed");

    // The key must open `previous`; otherwise nothing is produced.
    let wrong = encrypt(edited.as_bytes(), &[Key::password("another password")], &update);
    assert_eq!(wrong.unwrap_err().kind, ErrorKind::Auth);
    println!("previous with a key that does not open it: rejected (AUTH)");

    // --- seal: a checksum over the whole text; removed or reordered lines are detected --
    let sealed = encrypt(plain.as_bytes(), &keys, &EncryptOptions { seal: Some(true), ..fast.clone() })?;
    println!("\nseal: true\n{sealed}");
    let without_last_line = |text: &str| {
        let lines: Vec<&str> = text.lines().collect();
        lines[..lines.len() - 1].join("\n") + "\n"
    };
    let error = decrypt(without_last_line(&sealed).as_bytes(), &key).unwrap_err();
    assert_eq!(error.kind, ErrorKind::Auth);
    println!("sealed text with one line removed: rejected ({error})");
    // Unsealed, the same removal goes unnoticed: the remaining lines decrypt.
    let shortened = decrypt(without_last_line(&v1).as_bytes(), &key)?;
    println!("unsealed text with one line removed still decrypts, to {} lines instead of 6", String::from_utf8(shortened)?.lines().count());

    // --- options not given are taken from `previous` -------------------------------------
    let sealed_v2 = encrypt(edited.as_bytes(), &keys, &EncryptOptions { previous: Some(sealed.clone().into_bytes()), ..Default::default() })?;
    match inspect(sealed_v2.as_bytes())? {
        InspectResult::Lines { seal, .. } => assert!(seal),
        InspectResult::Blob { .. } => unreachable!(),
    }
    println!("an update of a sealed text is sealed again: {}", inspect(sealed_v2.as_bytes())?.to_json());

    // --- all decrypt to what was encrypted, with no options -----------------------------
    for encrypted in [&v1, &no_ws, &pad0, &pad64, &sealed] {
        assert_eq!(decrypt(encrypted.as_bytes(), &key)?, plain.as_bytes());
    }
    println!("\nall variants decrypt to the original without any option: ok");
    Ok(())
}
