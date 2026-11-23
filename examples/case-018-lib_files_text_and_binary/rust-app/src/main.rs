// case-018: encrypt a text file line by line and a binary file as a blob; read the
// encrypted files back, look at them without a key, decrypt them.
use ssenc::{decrypt, detect_mode, encrypt, inspect, EncryptOptions, InspectResult, Key, Mode};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = Key::password(fs::read_to_string("tmp/password.txt")?.trim());

    // --- a text file: lines mode (the default) ----------------------------------------
    let config = fs::read("tmp/config.yml")?;
    let config_encrypted = encrypt(&config, &[key.clone()], &EncryptOptions::default())?;
    fs::write("tmp/config.yml.enc", &config_encrypted)?; // the result is text
    println!("tmp/config.yml.enc:\n{config_encrypted}");

    // --- a binary file: blob mode ---------------------------------------------------------
    let photo = fs::read("tmp/photo.bin")?;
    let blob = EncryptOptions { mode: Some(Mode::Blob), ..Default::default() };
    let photo_encrypted = encrypt(&photo, &[key.clone()], &blob)?;
    fs::write("tmp/photo.bin.enc", &photo_encrypted)?;
    println!("tmp/photo.bin.enc: {} bytes became {} characters of ASCII, first lines:", photo.len(), photo_encrypted.len());
    for line in photo_encrypted.lines().take(4) {
        println!("{line}");
    }

    // --- inspect: no key needed -------------------------------------------------------------
    let info = inspect(&fs::read("tmp/config.yml.enc")?)?;
    println!("\ninspect config as JSON: {}", info.to_json());
    match inspect(&fs::read("tmp/photo.bin.enc")?)? {
        InspectResult::Blob { chunk, slots } => println!("inspect photo: blob mode, chunk {chunk}, slots {slots:?}"),
        InspectResult::Lines { .. } => unreachable!("the photo was encrypted in blob mode"),
    }

    // --- decrypt: mode and settings are read from the encrypted text ----------------------
    let config_back = decrypt(&fs::read("tmp/config.yml.enc")?, &key)?;
    let photo_back = decrypt(&fs::read("tmp/photo.bin.enc")?, &key)?;
    fs::write("tmp/photo.decrypted.bin", &photo_back)?;
    assert_eq!(config_back, config);
    assert_eq!(photo_back, photo);
    println!("\nboth files decrypt to exactly the original bytes: ok");

    // --- blob mode with a smaller chunk size ----------------------------------------------
    let small_chunks = EncryptOptions { mode: Some(Mode::Blob), chunk: Some(4096), ..Default::default() };
    let small = encrypt(&photo, &[key.clone()], &small_chunks)?;
    println!("chunk 4096: {}", inspect(small.as_bytes())?.to_json());
    assert_eq!(decrypt(small.as_bytes(), &key)?, photo);
    println!("the file with small chunks decrypts to the original as well: ok");

    // --- Mode::Auto: lines for text (no NUL byte, valid UTF-8), blob for anything else ------
    println!("\ndetect_mode: config {:?}, photo {:?}", detect_mode(&config), detect_mode(&photo));
    let auto = EncryptOptions { mode: Some(Mode::Auto), ..Default::default() };
    let config_auto = encrypt(&config, &[key.clone()], &auto)?;
    let photo_auto = encrypt(&photo, &[key.clone()], &auto)?;
    assert!(config_auto.starts_with("#ssenc1 lines "));
    assert!(photo_auto.starts_with("#ssenc1 blob "));
    println!("Mode::Auto: the text file was encrypted line by line, the binary file as a blob: ok");

    // With previous, Auto keeps the mode of the previous version whatever the new content is.
    let update = EncryptOptions { mode: Some(Mode::Auto), previous: Some(config_auto.into_bytes()), ..Default::default() };
    let still_lines = encrypt(&photo[..100], &[key.clone()], &update)?;
    assert!(still_lines.starts_with("#ssenc1 lines "));
    println!("Mode::Auto with previous: the mode of the previous version is kept: ok");
    Ok(())
}
