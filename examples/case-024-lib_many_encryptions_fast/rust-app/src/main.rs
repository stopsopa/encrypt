// case-024: many encryptions, fast.
// Each operation with a password runs Argon2id once, on purpose slow. That cost protects
// passwords a person could guess; a random 256-bit key needs none of it.
use ssenc::{decrypt, encrypt, EncryptOptions, Error, Key};
use std::fs;
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut names: Vec<String> = fs::read_dir("tmp/plain")?.map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned())).collect::<Result<_, std::io::Error>>()?;
    names.sort();

    // --- 1. the default cost, 3 files --------------------------------------------------
    let password = Key::password(fs::read_to_string("tmp/password.txt")?.trim());
    let start = Instant::now();
    for name in &names[..3] {
        encrypt(&fs::read(format!("tmp/plain/{name}"))?, &[password.clone()], &EncryptOptions::default())?;
    }
    println!("default cost:  3 files encrypted in {:.2} s", start.elapsed().as_secs_f64());

    // --- 2. a random key and the minimum cost, all 60 files -----------------------------
    let bulk_key = Key::password(fs::read_to_string("tmp/bulk.key")?.trim());
    let minimum = EncryptOptions { kdf: Some("m=8,t=1,p=1".into()), ..Default::default() };
    let start = Instant::now();
    for name in &names {
        let encrypted = encrypt(&fs::read(format!("tmp/plain/{name}"))?, &[bulk_key.clone()], &minimum)?;
        fs::write(format!("tmp/fast/{name}.enc"), encrypted)?;
    }
    println!("minimum cost: {} files encrypted in {:.3} s", names.len(), start.elapsed().as_secs_f64());

    // --- 3. decrypting needs no option: the cost is stored in every file ----------------
    let start = Instant::now();
    for name in &names {
        let plain = decrypt(&fs::read(format!("tmp/fast/{name}.enc"))?, &bulk_key)?;
        assert_eq!(plain, fs::read(format!("tmp/plain/{name}"))?);
    }
    println!("              {} files decrypted in {:.3} s, all identical to the originals", names.len(), start.elapsed().as_secs_f64());

    // --- 4. updating all of them (previous) is just as fast -----------------------------
    let start = Instant::now();
    for name in &names {
        let previous = fs::read_to_string(format!("tmp/fast/{name}.enc"))?;
        let edited = fs::read_to_string(format!("tmp/plain/{name}"))? + "added: yes\n";
        let update = EncryptOptions { previous: Some(previous.clone().into_bytes()), ..Default::default() };
        let updated = encrypt(edited.as_bytes(), &[bulk_key.clone()], &update)?;
        assert_eq!(updated.lines().filter(|line| !previous.lines().any(|old| old == *line)).count(), 1);
    }
    println!("              {} files updated in {:.3} s, one new line in each", names.len(), start.elapsed().as_secs_f64());

    // --- 5. the files are independent: use all cores -------------------------------------
    // Also the way to go when the password cost must stay: here the DEFAULT cost on threads.
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).min(8);
    let batch = &names[..threads * 2];
    let start = Instant::now();
    let results: Vec<Result<String, Error>> = std::thread::scope(|scope| {
        let handles: Vec<_> = batch
            .chunks(2)
            .map(|chunk| {
                let key = password.clone();
                scope.spawn(move || {
                    let mut last = Ok(String::new());
                    for name in chunk {
                        let plain = fs::read(format!("tmp/plain/{name}")).expect("readable file");
                        last = encrypt(&plain, &[key.clone()], &EncryptOptions::default());
                    }
                    last
                })
            })
            .collect();
        handles.into_iter().map(|handle| handle.join().expect("thread finished")).collect()
    });
    for result in results {
        result?;
    }
    println!("\ndefault cost: {} files encrypted on {threads} threads in {:.2} s (each thread needs 64 MiB while it derives a key)", batch.len(), start.elapsed().as_secs_f64());

    println!("\nNEVER use the minimum cost with a password a person chose: guessing it would be cheap.");
    Ok(())
}
