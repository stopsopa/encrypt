//! Known-answer tests against the vectors shared by all implementations (`tests/vectors`).

use ssenc::prim::{argon2id, hkdf32, SivKey};
use ssenc::{decrypt, detect_mode, encrypt, inspect, EncryptOptions, ErrorKind, Key, Mode};
use std::collections::BTreeMap;
use std::path::PathBuf;

// --- a JSON reader just big enough for the vector files ---------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.s.len() && self.s[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }

    fn eat(&mut self, lit: &str) -> bool {
        let hit = self.s[self.i..].starts_with(lit.as_bytes());
        if hit {
            self.i += lit.len();
        }
        hit
    }

    fn string(&mut self) -> String {
        assert!(self.eat("\""), "expected a string at byte {}", self.i);
        let mut out = Vec::new();
        loop {
            let c = self.s[self.i];
            self.i += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = self.s[self.i];
                    self.i += 1;
                    match e {
                        b'n' => out.push(b'\n'),
                        b't' => out.push(b'\t'),
                        b'r' => out.push(b'\r'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'u' => {
                            let hex = std::str::from_utf8(&self.s[self.i..self.i + 4]).unwrap();
                            self.i += 4;
                            let ch = char::from_u32(u32::from_str_radix(hex, 16).unwrap())
                                .expect("no surrogates in vectors");
                            out.extend_from_slice(ch.encode_utf8(&mut [0; 4]).as_bytes());
                        }
                        other => out.push(other),
                    }
                }
                c => out.push(c),
            }
        }
        String::from_utf8(out).unwrap()
    }

    fn value(&mut self) -> Json {
        self.ws();
        let first = self.s[self.i];
        let v = match first {
            b'{' => {
                self.i += 1;
                let mut map = BTreeMap::new();
                loop {
                    self.ws();
                    if self.eat("}") {
                        break;
                    }
                    let key = self.string();
                    self.ws();
                    assert!(self.eat(":"));
                    map.insert(key, self.value());
                    self.ws();
                    self.eat(",");
                }
                Json::Obj(map)
            }
            b'[' => {
                self.i += 1;
                let mut items = Vec::new();
                loop {
                    self.ws();
                    if self.eat("]") {
                        break;
                    }
                    items.push(self.value());
                    self.ws();
                    self.eat(",");
                }
                Json::Arr(items)
            }
            b'"' => Json::Str(self.string()),
            _ if self.eat("null") => Json::Null,
            _ if self.eat("true") => Json::Bool(true),
            _ if self.eat("false") => Json::Bool(false),
            _ => {
                let start = self.i;
                while self.i < self.s.len() && matches!(self.s[self.i], b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')
                {
                    self.i += 1;
                }
                Json::Num(
                    std::str::from_utf8(&self.s[start..self.i])
                        .unwrap()
                        .parse()
                        .expect("a JSON value"),
                )
            }
        };
        self.ws();
        v
    }
}

impl Json {
    fn parse(text: &[u8]) -> Json {
        let mut p = Parser { s: text, i: 0 };
        let v = p.value();
        assert_eq!(p.i, text.len(), "trailing data after JSON value");
        v
    }
    fn get(&self, key: &str) -> &Json {
        match self {
            Json::Obj(m) => m.get(key).unwrap_or_else(|| panic!("missing key {key}")),
            other => panic!("not an object: {other:?}"),
        }
    }
    fn has(&self, key: &str) -> bool {
        matches!(self, Json::Obj(m) if m.contains_key(key))
    }
    fn arr(&self) -> &[Json] {
        match self {
            Json::Arr(a) => a,
            other => panic!("not an array: {other:?}"),
        }
    }
    fn str(&self) -> &str {
        match self {
            Json::Str(s) => s,
            other => panic!("not a string: {other:?}"),
        }
    }
    fn num(&self) -> u32 {
        match self {
            Json::Num(n) => *n as u32,
            other => panic!("not a number: {other:?}"),
        }
    }
    fn hex(&self) -> Vec<u8> {
        let s = self.str();
        assert_eq!(s.len() % 2, 0);
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|c| format!("{c:02x}")).collect()
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tests")
        .join("vectors")
}

fn read(path: PathBuf) -> Vec<u8> {
    std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn primitives() -> Json {
    Json::parse(&read(vectors_dir().join("primitives.json")))
}

// --- primitives.json --------------------------------------------------------------------

#[test]
fn hkdf32_vectors() {
    let all = primitives();
    let list = all.get("hkdf32").arr();
    assert!(!list.is_empty());
    for v in list {
        let salt = match v.get("salt") {
            Json::Null => None,
            s => Some(s.hex()),
        };
        let out = hkdf32(&v.get("ikm").hex(), salt.as_deref(), v.get("info").str().as_bytes());
        assert_eq!(to_hex(&out), v.get("out").str(), "info {}", v.get("info").str());
    }
}

#[test]
fn siv_vectors() {
    let all = primitives();
    let list = all.get("siv").arr();
    assert!(!list.is_empty());
    for (i, v) in list.iter().enumerate() {
        let (ad, pt, out) = (v.get("ad").hex(), v.get("pt").hex(), v.get("out").hex());
        let derived = SivKey::derive(&v.get("parent").hex(), v.get("purpose").str());
        assert_eq!(to_hex(derived.kmac()), v.get("kmac").str(), "siv[{i}] kmac");
        assert_eq!(to_hex(derived.kenc()), v.get("kenc").str(), "siv[{i}] kenc");
        let raw = SivKey::from_raw(
            v.get("kmac").hex().try_into().unwrap(),
            v.get("kenc").hex().try_into().unwrap(),
        );
        for key in [&derived, &raw] {
            assert_eq!(to_hex(&key.encrypt(&ad, &pt)), to_hex(&out), "siv[{i}] encrypt");
            assert_eq!(key.decrypt(&ad, &out).unwrap(), pt, "siv[{i}] decrypt");
            let mut bad = out.clone();
            *bad.last_mut().unwrap() ^= 1;
            assert_eq!(
                key.decrypt(&ad, &bad).unwrap_err().kind,
                ErrorKind::Auth,
                "siv[{i}] tamper"
            );
            let mut bad_ad = ad.clone();
            bad_ad.push(0);
            assert_eq!(
                key.decrypt(&bad_ad, &out).unwrap_err().kind,
                ErrorKind::Auth,
                "siv[{i}] ad"
            );
            assert_eq!(
                key.decrypt(&ad, &out[..15]).unwrap_err().kind,
                ErrorKind::Malformed,
                "siv[{i}] short"
            );
        }
    }
}

#[test]
fn argon2id_vectors() {
    let all = primitives();
    let list = all.get("argon2id").arr();
    assert!(!list.is_empty());
    for (i, v) in list.iter().enumerate() {
        let out = argon2id(
            v.get("password").str().as_bytes(),
            &v.get("salt").hex(),
            v.get("m").num(),
            v.get("t").num(),
            v.get("p").num(),
        )
        .unwrap();
        assert_eq!(to_hex(&out), v.get("out").str(), "argon2id[{i}]");
    }
}

// --- file vectors -----------------------------------------------------------------------

#[test]
fn password_file_vectors() {
    let list = Json::parse(&read(vectors_dir().join("vectors.json")));
    let mut checked = 0;
    for v in list.arr() {
        let name = v.get("name").str();
        let dir = vectors_dir().join(name);
        let encrypted = read(dir.join("encrypted.txt"));
        // Every vector, whatever its key, must at least be recognised.
        inspect(&encrypted).unwrap_or_else(|e| panic!("{name}: inspect: {e}"));
        if !v.get("key").has("password") {
            continue; // ssh vectors need an agent; the cross-implementation suite covers them
        }
        let key = Key::password(v.get("key").get("password").str());
        let plain = read(dir.join("plain.bin"));

        let got = decrypt(&encrypted, &key).unwrap_or_else(|e| panic!("{name}: decrypt: {e}"));
        assert_eq!(got, plain, "{name}: decrypt");

        let opts = EncryptOptions {
            previous: Some(encrypted.clone()),
            ..Default::default()
        };
        let again = encrypt(&plain, &[key], &opts).unwrap_or_else(|e| panic!("{name}: encrypt: {e}"));
        assert_eq!(again.as_bytes(), encrypted, "{name}: re-encrypt with previous");

        let wrong = Key::password("definitely not the password");
        assert_eq!(
            decrypt(&encrypted, &wrong).unwrap_err().kind,
            ErrorKind::Auth,
            "{name}: wrong password"
        );
        checked += 1;
    }
    assert!(checked >= 9, "only {checked} password vectors found");
}

#[test]
fn inspect_json_of_vectors() {
    let json = |name: &str| {
        inspect(&read(vectors_dir().join(name).join("encrypted.txt")))
            .unwrap()
            .to_json()
    };
    assert_eq!(
        json("lines-kdf-default"),
        r#"{"format":"ssenc1","mode":"lines","ws":true,"pad":16,"seal":false,"slots":[{"type":"pw","kdf":"argon2id","m":65536,"t":3,"p":4}]}"#
    );
    assert!(json("blob-ssh-rsa").starts_with(r#"{"format":"ssenc1","mode":"blob","chunk":"#));
    assert!(json("blob-ssh-rsa").contains(r#""slots":[{"type":"ssh","keyType":"ssh-rsa","fingerprint":"SHA256:"#));
}

// --- auto-mode.json: what `Mode::Auto` picks, identical in every implementation ----------

#[test]
fn auto_mode_vectors() {
    let all = Json::parse(&read(vectors_dir().join("auto-mode.json")));
    let key = Key::password("pw");
    let auto = EncryptOptions {
        mode: Some(Mode::Auto),
        kdf: Some("m=8,t=1,p=1".into()),
        ..Default::default()
    };
    let (mut lines, mut blobs) = (0, 0);
    for v in all.arr() {
        let name = v.get("name").str();
        let input = v.get("hex").hex();
        let want = match v.get("mode").str() {
            "lines" => Mode::Lines,
            "blob" => Mode::Blob,
            other => panic!("{name}: unknown mode {other}"),
        };
        assert_eq!(detect_mode(&input), want, "{name}: detect_mode");
        let encrypted =
            encrypt(&input, std::slice::from_ref(&key), &auto).unwrap_or_else(|e| panic!("{name}: encrypt: {e}"));
        let header = format!("#ssenc1 {} ", want.as_str());
        assert!(
            encrypted.starts_with(&header),
            "{name}: expected a {} file",
            want.as_str()
        );
        assert_eq!(
            decrypt(encrypted.as_bytes(), &key).unwrap(),
            input,
            "{name}: round trip"
        );
        match want {
            Mode::Lines => lines += 1,
            _ => blobs += 1,
        }
    }
    assert!(
        lines >= 15 && blobs >= 20,
        "only {lines} text and {blobs} binary inputs found"
    );
}

#[test]
fn auto_mode_with_previous_keeps_its_mode() {
    let key = [Key::password("pw")];
    let auto = EncryptOptions {
        mode: Some(Mode::Auto),
        kdf: Some("m=8,t=1,p=1".into()),
        ..Default::default()
    };
    let (text, binary) = (b"a\nb\n".as_slice(), b"a\n\xff\x00\n".as_slice());
    let with_previous = |mode: Option<Mode>, previous: &str| EncryptOptions {
        mode,
        previous: Some(previous.as_bytes().to_vec()),
        ..Default::default()
    };

    // text first, then binary content: the file stays in lines mode, and one line differs
    let v1 = encrypt(text, &key, &auto).unwrap();
    assert!(v1.starts_with("#ssenc1 lines "));
    let v2 = encrypt(binary, &key, &with_previous(Some(Mode::Auto), &v1)).unwrap();
    assert!(v2.starts_with("#ssenc1 lines "));
    assert_eq!(decrypt(v2.as_bytes(), &key[0]).unwrap(), binary);
    let changed = v1.lines().zip(v2.lines()).filter(|(a, b)| a != b).count();
    assert_eq!(changed, 1, "only the edited line may change");

    // binary first, then text: the file stays a blob
    let b1 = encrypt(binary, &key, &auto).unwrap();
    assert!(b1.starts_with("#ssenc1 blob "));
    let b2 = encrypt(text, &key, &with_previous(Some(Mode::Auto), &b1)).unwrap();
    assert!(b2.starts_with("#ssenc1 blob "));
    assert_eq!(decrypt(b2.as_bytes(), &key[0]).unwrap(), text);

    // an explicit mode still wins over the previous version
    let forced = encrypt(text, &key, &with_previous(Some(Mode::Lines), &b1)).unwrap();
    assert!(forced.starts_with("#ssenc1 lines "));

    // auto + seal: fine for text, refused when the input turns out to be binary
    let sealed = EncryptOptions {
        seal: Some(true),
        ..auto.clone()
    };
    assert!(encrypt(text, &key, &sealed).unwrap().contains("\n#seal "));
    assert_eq!(encrypt(binary, &key, &sealed).unwrap_err().kind, ErrorKind::Usage);
}
